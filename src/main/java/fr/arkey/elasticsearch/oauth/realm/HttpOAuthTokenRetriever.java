package fr.arkey.elasticsearch.oauth.realm;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import okhttp3.ConnectionPool;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.shield.authc.RealmConfig;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static org.elasticsearch.common.xcontent.json.JsonXContent.jsonXContent;

public class HttpOAuthTokenRetriever implements OAuthTokenRetriever {
    private final ESLogger logger;
    private static final int MAX_TOTAL_CONNECTION = 200;
    private static final long CONNECT_TIMEOUT = 10_000L;
    private static final long SOCKET_TIMEOUT = 10_000L;
    private final String tokenInfoUri;
    private final Function<Map<String, Object>, TokenInfo> tokenInfoMapper;

    private OkHttpClient httpClient;

    protected HttpOAuthTokenRetriever(RealmConfig config,
                                      Function<Map<String, Object>, TokenInfo> tokenInfoMapper) {
        Objects.requireNonNull(config);
        this.tokenInfoMapper = Objects.requireNonNull(tokenInfoMapper);
        this.logger = config.logger(HttpOAuthTokenRetriever.class);
        this.tokenInfoUri = config.settings().get("token-info.url");
        this.httpClient = createIdpHttpClient(
                config.settings().getAsLong("idp.connection-timeout-in-millis", CONNECT_TIMEOUT),
                config.settings().getAsLong("idp.read-timeout-in-millis", SOCKET_TIMEOUT),
                config.settings().getAsLong("idp.write-timeout-in-millis", SOCKET_TIMEOUT),
                config.settings().getAsInt("idp.max-idle-connections", MAX_TOTAL_CONNECTION)
        );
    }

    private OkHttpClient createIdpHttpClient(long connectionTimeoutInMillis,
                                             long readTimeoutInMillis,
                                             long writeTimeoutInMillis,
                                             int maxIdleConnections) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            // unprivileged code such as scripts do not have SpecialPermission
            sm.checkPermission(new SpecialPermission());
        }
        return AccessController.doPrivileged(
                (PrivilegedAction<OkHttpClient>) () -> {
                    logger.debug("Configuring OAuth http client with connection timeout : {}ms, socket read timeout : {}, socket write timeout : {}",
                                 connectionTimeoutInMillis,
                                 readTimeoutInMillis,
                                 writeTimeoutInMillis);

                    return new OkHttpClient.Builder()
                            .connectTimeout(connectionTimeoutInMillis, MILLISECONDS)
                            .readTimeout(readTimeoutInMillis, MILLISECONDS)
                            .writeTimeout(writeTimeoutInMillis, MILLISECONDS)
                            .connectionPool(new ConnectionPool(maxIdleConnections, 5, MINUTES))
                            .build();
                }
        );
    }

    @Override
    public Optional<TokenInfo> getTokenInfo(String accessToken) {
        try (Response tokenInfoResponse = executeRequest(
                new Request.Builder()
                        .url(tokenInfoUri)
                        .header("Accept", "application/json")
                        .header("Authorization", "Bearer " + accessToken)
                        .get()
                        .build())) {
            if (tokenInfoResponse.isSuccessful()) {
                ResponseBody body = tokenInfoResponse.body();
                Map<String, Object> jsonMap = jsonXContent.createParser(body.byteStream()).map();
                logger.debug("User authenticated via access token, token info : {}", jsonMap);
                return Optional.of(tokenInfoMapper.apply(jsonMap));
            }
            return Optional.empty();
        } catch (IOException ioe) {
            logger.error("Could not authenticate user, could be a connection issue", ioe);
            throw OAuthRealmExceptions.authorizationException(ioe);
        }
    }

    private Response executeRequest(Request req) throws IOException {
        return httpClient.newCall(req).execute();
    }

}
