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
package fr.arkey.elasticsearch.oauth.tools;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;
import okhttp3.Authenticator;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;
import okhttp3.logging.HttpLoggingInterceptor;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static fr.arkey.elasticsearch.oauth.tools.DebugDetector.debugging;

public class HttpClients {

    public static final String BEARER_PREFIX = "Bearer ";
    public static final String AUTHORIZATION_HEADER = "Authorization";

    public static OkHttpClient trustAllHttpClient() {

        // Create an ssl socket context with our all-trusting manager

        return new OkHttpClient.Builder()
                .sslSocketFactory(trustAllSslContext().getSocketFactory(), TrustAllX509TrustManager.INSTANCE)
                .connectTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .readTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .writeTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .addInterceptor(httpLoggingInterceptor())
                .build();
    }

    public static OkHttpClient httpClient(SSLContext sslContext) {
        return new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory())
                .connectTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .readTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .writeTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .addInterceptor(httpLoggingInterceptor())
                .build();
    }

    public static SSLContext sslContext(KeyManager[] keyManagers, TrustManager[] trustManagers) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers,
                            trustManagers,
                            null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException("Couldn't init TLS context", e);
        }
    }


    private static HttpLoggingInterceptor httpLoggingInterceptor() {
        return new HttpLoggingInterceptor(message -> System.out.println(message))
                .setLevel(debugging() ?
                          HttpLoggingInterceptor.Level.BODY :
                          HttpLoggingInterceptor.Level.NONE);
    }


//    private static X509KeyManager jksKeyManager(Path path, char[] pazzwort) {
//        try (InputStream fis = Files.newInputStream(path)) {
//            KeyStore jks = KeyStore.getInstance("JKS");
//            jks.load(fis, pazzwort);
//
//            KeyManagerFactory sunX509keyManager = KeyManagerFactory.getInstance("SunX509");
//            sunX509keyManager.init(jks, pazzwort);
//
//            KeyManager[] keyManagers = sunX509keyManager.getKeyManagers();
//            if (keyManagers.length != 1 || !(keyManagers[0] instanceof X509KeyManager)) {
//                throw new IllegalStateException("Unexpected default key managers:"
//                                                + Arrays.toString(keyManagers));
//            }
//            return (X509KeyManager) keyManagers[0];
//        } catch (IOException e) {
//            throw new UncheckedIOException(e);
//        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
//            throw new IllegalStateException("Couldn't init TLS with custom trust store '"
//                                            + path + "' and system trust manager", e);
//        }
//    }

    private static SSLContext trustAllSslContext() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null,
                            TrustAllX509TrustManager.singleInstanceTrustManagerArray(),
                            null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException("Couldn't init TLS with trust all X509 manager", e);
        }
    }

    public static TrustManager systemTrustManager() throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        if (trustManagers.length != 1) {
            throw new IllegalStateException("Unexpected default trust managers:"
                                            + Arrays.toString(trustManagers));
        }
        return trustManagers[0];
    }

    public static OkHttpClient simpleHttpClient() {
        return new OkHttpClient.Builder()
                .connectTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .readTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .writeTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .addInterceptor(httpLoggingInterceptor())
                .build();
    }

    public static OkHttpClient trustAllAuthenticatingClient(Authenticator authenticator) {
        return new OkHttpClient.Builder()
                .sslSocketFactory(trustAllSslContext().getSocketFactory(), TrustAllX509TrustManager.INSTANCE)
                .authenticator(authenticator)
                .connectTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .readTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .writeTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .addInterceptor(httpLoggingInterceptor())
                .build();
    }

    public static class OAuthClientGrantAuthenticator implements OAuthAuthenticator {
        final String tokenEndpoint;
        private ClientCredentials clientCredentials;
        private OkHttpClient okHttpClient;

        OAuthClientGrantAuthenticator(String tokenEndpoint, ClientCredentials clientCredentials) {
            this(tokenEndpoint,
                 clientCredentials,
                 trustAllHttpClient());
        }

        public OAuthClientGrantAuthenticator(String tokenEndpoint, ClientCredentials clientCredentials, OkHttpClient okHttpClient) {
            this.tokenEndpoint = tokenEndpoint;
            this.clientCredentials = clientCredentials;
            this.okHttpClient = okHttpClient;
        }

        @Override
        public Request authenticate(Route route, Response response) throws IOException {
            if (responseCount(response) >= 3) {
                return null;
            }

            return acquireAccessToken().map(OAuthAuthenticator::toBearer)
                                       .map(bearer -> response.request().newBuilder()
                                                              .header(AUTHORIZATION_HEADER, bearer)
                                                              .build())
                                       .orElse(null);
        }


        @Override
        public Optional<String> acquireAccessToken() {
            try (Response response = okHttpClient.newCall(
                    new Request.Builder()
                            .url(tokenEndpoint)
                            .post(new FormBody.Builder()
                                          .add("grant_type", "client_credentials")
                                          .add("client_id", clientCredentials.client_id)
                                          .add("client_secret", clientCredentials.client_secret)
                                          .build())
                            .build()).execute()) {

                if (response.isSuccessful()) {
                    OAuthTokenPayload oAuthTokenPayload = OAuthTokenPayload.JsonMapper.fromJson(response.body().string());
                    System.out.println(oAuthTokenPayload);
                    return Optional.of(oAuthTokenPayload.accessToken);
                }

                return Optional.empty();
            } catch (IOException ioe) {
                throw new UncheckedIOException(ioe);
            }
        }
    }

    public static class PasswordGrantOAuthAuthenticator implements OAuthAuthenticator {
        final String tokenEndpoint;
        private UserCredentials userCredentials;
        private ClientCredentials clientCredentials;
        private OkHttpClient okHttpClient;

        public PasswordGrantOAuthAuthenticator(String tokenEndpoint,
                                               UserCredentials userCredentials,
                                               ClientCredentials clientCredentials) {
            this(tokenEndpoint,
                 userCredentials,
                 clientCredentials,
                 trustAllHttpClient());
        }

        public PasswordGrantOAuthAuthenticator(String tokenEndpoint,
                                               UserCredentials userCredentials,
                                               ClientCredentials clientCredentials,
                                               OkHttpClient okHttpClient) {
            this.tokenEndpoint = tokenEndpoint;
            this.userCredentials = userCredentials;
            this.clientCredentials = clientCredentials;
            this.okHttpClient = okHttpClient;
        }

        @Override
        public Request authenticate(Route route, Response response) throws IOException {
            if (responseCount(response) >= 3) {
                return null;
            }

            return acquireAccessToken().map(OAuthAuthenticator::toBearer)
                                       .map(bearer -> response.request().newBuilder()
                                                              .header(AUTHORIZATION_HEADER, bearer)
                                                              .build())
                                       .orElse(null);
        }

        public Optional<String> acquireAccessToken() {
            try (Response response = okHttpClient.newCall(
                    new Request.Builder()
                            .url(tokenEndpoint)
                            .post(new FormBody.Builder()
                                          .add("grant_type", "password")
                                          .add("username", userCredentials.username)
                                          .add("password", userCredentials.password)
                                          .add("client_id", clientCredentials.client_id)
                                          .add("client_secret", clientCredentials.client_secret)
                                          .build())
                            .build()).execute()) {

                if (response.isSuccessful()) {
                    OAuthTokenPayload oAuthTokenPayload = OAuthTokenPayload.JsonMapper.fromJson(response.body().string());
                    System.out.println(oAuthTokenPayload);
                    return Optional.of(oAuthTokenPayload.accessToken);
                }

                return Optional.empty();
            } catch (IOException ioe) {
                throw new UncheckedIOException(ioe);
            }
        }
    }

    public abstract static class AlternateTrustManager implements TrustManager {
        public static TrustManager[] singleAlternateTrustManagerAsArray(Path javaKeyStorePath, String password) {
            return new TrustManager[]{trustManager(javaKeyStorePath, password)};
        }

        public static TrustManager trustManager(Path javaKeyStorePath, String password) {
            try {
                KeyStore keyStore = readJavaKeyStore(javaKeyStorePath, password);
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(keyStore);

                TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
                if (trustManagers.length != 1) {
                    throw new IllegalStateException("Unexpected number of trust managers:"
                                                    + Arrays.toString(trustManagers));
                }
                return trustManagers[0];
            } catch (NoSuchAlgorithmException | KeyStoreException e) {
                throw new IllegalStateException(e);
            }
        }

        static KeyStore readJavaKeyStore(Path javaKeyStorePath, String password) {
            try(InputStream inputStream = new BufferedInputStream(Files.newInputStream(javaKeyStorePath))) {
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(inputStream, password.toCharArray());
                return ks;
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
                throw new IllegalStateException(e);
            }
        }

    }

    private static class TrustAllX509TrustManager implements X509TrustManager {
        public static final TrustAllX509TrustManager INSTANCE = new TrustAllX509TrustManager();

        private TrustAllX509TrustManager() {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        public static TrustManager[] singleInstanceTrustManagerArray() {
            return new TrustManager[]{INSTANCE};
        }
    }

    public interface OAuthAuthenticator extends Authenticator {
        Optional<String> acquireAccessToken();

        static String toBearer(String token) {
            return BEARER_PREFIX + token;
        }

        default int responseCount(Response response) {
            int result = 1;
            while ((response = response.priorResponse()) != null) {
                result++;
            }
            return result;
        }
    }
}
