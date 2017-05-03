package fr.arkey.elasticsearch.oauth.realm;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import okhttp3.ConnectionPool;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.shield.authc.RealmConfig;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.elasticsearch.common.xcontent.json.JsonXContent.jsonXContent;

public class OAuthVerifier {
    private final ESLogger logger;
    private static final int MAX_TOTAL_CONNECTION = 200;
    private static final long CONNECT_TIMEOUT = 10_000L;
    private static final long SOCKET_TIMEOUT = 10_000L;
    private final String tokenInfoUri;
    private final String tokenInfoUserField;
    private final String tokenInfoExpiresIn;

    private OkHttpClient httpClient;
    private RealmConfig config;

    protected OAuthVerifier(RealmConfig config) {
        this.config = config;
        logger = config.logger(OAuthVerifier.class);

        tokenInfoUri = config.settings().get("token-info-url");

        tokenInfoUserField = config.settings().get("token-info.user.field");
        tokenInfoExpiresIn = config.settings().get("token-info.expires-in.field");
        TimeUnit tokenInfoExpiresInUnit = TimeUnit.valueOf(config.settings().get("token-info.expires-in.field.unit",
                                                                                 SECONDS.name()).toUpperCase(Locale.getDefault()));

        httpClient = createIdpHttpClient(config.settings());
    }

    private OkHttpClient createIdpHttpClient(Settings settings) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            // unprivileged code such as scripts do not have SpecialPermission
            sm.checkPermission(new SpecialPermission());
        }
        return AccessController.doPrivileged(
                (PrivilegedAction<OkHttpClient>) () -> {
                    long connectionTimeoutInMillis = settings.getAsLong("idp.connection-timeout-in-millis", CONNECT_TIMEOUT);
                    long readTimeoutInMillis = settings.getAsLong("idp.read-timeout-in-millis", SOCKET_TIMEOUT);
                    long writeTimeoutInMillis = settings.getAsLong("idp.write-timeout-in-millis", SOCKET_TIMEOUT);
                    int maxIdleConnections = settings.getAsInt("idp.max-idle-connections", MAX_TOTAL_CONNECTION);

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

    public Optional<Map<String, Object>> performTokenInfoRequest(String token) {
        try (Response tokenInfoResponse = executeRequest(new Request.Builder()
                .url(tokenInfoUri)
                .header("Accept", "application/json")
                .header("Authorization", "Bearer " + token)
                .get()
                .build())) {
            if (tokenInfoResponse.isSuccessful()) {
                ResponseBody body = tokenInfoResponse.body();
                Map<String, Object> jsonMap = jsonXContent.createParser(body.byteStream()).map();
                logger.debug("User authenticated via access token, token info : {}", jsonMap);
                return Optional.of(new HashMap<>(jsonMap));
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
