/*
 * Copyright 2017 Brice Dutheil
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fr.arkey.elasticsearch.oauth.realm.tokeninfo;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.UnknownHostException;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import fr.arkey.elasticsearch.oauth.realm.support.OAuthRealmExceptions;
import fr.arkey.elasticsearch.oauth.realm.support.Privileges;
import okhttp3.Authenticator;
import okhttp3.ConnectionPool;
import okhttp3.Credentials;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.Strings;
import org.elasticsearch.xpack.security.authc.RealmConfig;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.stream.Collectors.joining;
import static okhttp3.CacheControl.FORCE_NETWORK;

/**
 * Token info retriever that will query the token endpoint.
 *
 * The http client needs a single token url, and will query the token info using a given access token.
 * The http client is configured with default timeouts, and default connection pool, however
 * these are configurable.
 * If a proxy is configured for the idp, it will be used.
 */
public class HttpOAuthTokenRetriever implements OAuthTokenRetriever {
    private final Logger logger;
    private static final int MAX_TOTAL_CONNECTION = 200;
    private static final long CONNECT_TIMEOUT = 10_000L;
    private static final long SOCKET_TIMEOUT = 10_000L;
    private final String tokenInfoUri;
    private final Function<InputStream, TokenInfo> tokenInfoMapper;
    private final OkHttpClient httpClient;
    private final String name;

    /**
     * Build the token info retriever.
     *
     * @param config          the realm config where to find settings
     * @param tokenInfoMapper the mapper that can read the token info as a Map to a TokenInfo object
     */
    public HttpOAuthTokenRetriever(RealmConfig config,
                                   Function<InputStream, TokenInfo> tokenInfoMapper) {
        Objects.requireNonNull(config);
        this.name = Objects.requireNonNull(config.name());
        this.tokenInfoMapper = Objects.requireNonNull(tokenInfoMapper);
        this.logger = config.logger(HttpOAuthTokenRetriever.class);
        this.tokenInfoUri = Objects.requireNonNull(config.settings().get("token-info.url"), "missing required setting [token-info.url]");


        this.httpClient = createIdpHttpClient(
                config.settings().getAsLong("idp.connection-timeout-in-millis", CONNECT_TIMEOUT),
                config.settings().getAsLong("idp.read-timeout-in-millis", SOCKET_TIMEOUT),
                config.settings().getAsLong("idp.write-timeout-in-millis", SOCKET_TIMEOUT),
                config.settings().getAsInt("idp.max-idle-connections", MAX_TOTAL_CONNECTION),
                () -> proxyFrom(config),
                () -> proxyAuthenticatorFrom(config)
        );

        logHttpClientSettings();
    }

    private void logHttpClientSettings() {
        Optional<String> resolved = tryResolveUri();

        logger.debug("[{}] OAuth realm HTTP client settings :\n" +
                     "  proxy : {} {}\n" +
                     "  connection timeout : {} ms\n" +
                     "  write timeout : {} ms\n" +
                     "  read timeout : {} ms\n" +
                     "  resolved IPs for '{}' : {}",
                     name,
                     httpClient.proxyAuthenticator() != Authenticator.NONE ? "<authenticated>" : "<un-authenticated>",
                     httpClient.proxy() != null ? httpClient.proxy().address() : "<none>",
                     httpClient.connectTimeoutMillis(),
                     httpClient.writeTimeoutMillis(),
                     httpClient.readTimeoutMillis(),
                     tokenInfoUri,
                     resolved.orElse("unresolved at this time"));
    }

    private Optional<String> tryResolveUri() {
        try {
            return Optional.of(httpClient.dns().lookup(HttpUrl.parse(tokenInfoUri).host()).stream().map(Object::toString).collect(joining(",")));
        } catch (UnknownHostException e) {
            return Optional.empty();
        }
    }

    /**
     * Perform the HTTP GET request to the provided URL.
     *
     * It uses the provided access token as Authentication on the token endpoint.
     *
     * @param accessToken The access token
     * @return An optional containing the token info if it exists
     */
    @Override
    public Optional<TokenInfo> getTokenInfo(String accessToken) {
        try (Response tokenInfoResponse = executeRequest(
                new Request.Builder()
                        .url(tokenInfoUri)
                        .header("Accept", "application/json")
                        .header("Authorization", "Bearer " + accessToken)
                        .cacheControl(FORCE_NETWORK)
                        .get()
                        .build())) {
            if (tokenInfoResponse.isSuccessful()) {
                return Optional.of(tokenInfoMapper.apply(tokenInfoResponse.body().byteStream()));
            } else if (tokenInfoResponse.headers().names().contains("WWW-Authenticate")) {
                throw OAuthRealmExceptions.authorizationException(tokenInfoResponse.header("WWW-Authenticate"));
            }
            return Optional.empty();
        } catch (UncheckedIOException | IOException ioe) {
            logger.error("Could not authenticate user, could be a connection issue", ioe);
            throw OAuthRealmExceptions.authorizationException(ioe);
        }
    }

    private Optional<Authenticator> proxyAuthenticatorFrom(RealmConfig config) {
        String proxyUserName = config.settings().get("idp.proxy.username");

        if (config.settings().get("idp.proxy.host") == null
            || Strings.isEmpty(proxyUserName)) {
            return Optional.empty();
        }
        String proxyPassword = Objects.requireNonNull(config.settings().get("idp.proxy.password"), "missing required setting [idp.proxy.password]");

        return Optional.of((route, response) -> response.request()
                                                        .newBuilder()
                                                        .header("Proxy-Authorization",
                                                                Credentials.basic(proxyUserName, proxyPassword))
                                                        .build());

    }


    private Optional<Proxy> proxyFrom(RealmConfig config) {
        String proxyHost = config.settings().get("idp.proxy.host");
        if (Strings.isEmpty(proxyHost)) {
            return Optional.empty();
        }
        int proxyPort = Objects.requireNonNull(config.settings().getAsInt("idp.proxy.port", null), "missing required setting [idp.proxy.port]");

        return Optional.of(new Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved(proxyHost, proxyPort)));
    }

    private OkHttpClient createIdpHttpClient(long connectionTimeoutInMillis,
                                             long readTimeoutInMillis,
                                             long writeTimeoutInMillis,
                                             int maxIdleConnections,
                                             Supplier<Optional<Proxy>> proxySupplier,
                                             Supplier<Optional<Authenticator>> proxyAuthenticatorSupplier) {
        // require some special privileges to create the HTTP client
        return Privileges.pluginPrivileges(() -> {
            logger.debug("Configuring OAuth http client with connection timeout : {}ms, socket read timeout : {}, socket write timeout : {}",
                         connectionTimeoutInMillis,
                         readTimeoutInMillis,
                         writeTimeoutInMillis);

            OkHttpClient.Builder okHttpClientBuilder = new OkHttpClient.Builder()
                    .connectTimeout(connectionTimeoutInMillis, MILLISECONDS)
                    .readTimeout(readTimeoutInMillis, MILLISECONDS)
                    .writeTimeout(writeTimeoutInMillis, MILLISECONDS)
                    .connectionPool(new ConnectionPool(maxIdleConnections, 5, MINUTES));

            proxySupplier.get().ifPresent(okHttpClientBuilder::proxy);
            proxyAuthenticatorSupplier.get().ifPresent(okHttpClientBuilder::proxyAuthenticator);
            return okHttpClientBuilder.build();
        });
    }

    private Response executeRequest(Request req) throws IOException {
        return httpClient.newCall(req).execute();
    }

}
