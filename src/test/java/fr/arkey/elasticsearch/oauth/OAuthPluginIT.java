package fr.arkey.elasticsearch.oauth;

import java.io.IOException;
import java.nio.file.Paths;
import fr.arkey.elasticsearch.oauth.tools.ClientCredentials;
import fr.arkey.elasticsearch.oauth.tools.ESClient;
import fr.arkey.elasticsearch.oauth.tools.HttpClients.OAuthAuthenticator;
import fr.arkey.elasticsearch.oauth.tools.HttpClients.OAuthClientGrantAuthenticator;
import fr.arkey.elasticsearch.oauth.tools.HttpClients.PasswordGrantOAuthAuthenticator;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.Rule;
import org.junit.Test;

import static fr.arkey.elasticsearch.oauth.tools.ClientCredentials.clientCredentials;
import static fr.arkey.elasticsearch.oauth.tools.HttpClients.AlternateTrustManager.singleAlternateTrustManagerAsArray;
import static fr.arkey.elasticsearch.oauth.tools.HttpClients.BEARER_PREFIX;
import static fr.arkey.elasticsearch.oauth.tools.HttpClients.httpClient;
import static fr.arkey.elasticsearch.oauth.tools.HttpClients.sslContext;
import static fr.arkey.elasticsearch.oauth.tools.HttpClients.trustAllHttpClient;
import static fr.arkey.elasticsearch.oauth.tools.UserCredentials.userCredentials;
import static org.assertj.core.api.Assertions.assertThat;

public class OAuthPluginIT {
    private String esUrl = "http://localhost:9400/";
    //    private String tokenEndpoint = "https://internal.domain.com:8443/nidp/oauth/nam/token";
    private String tokenEndpoint = "https://idp.lab.company.io/nidp/oauth/nam/token";
    private ClientCredentials companyLabClientCredentials = clientCredentials("39e8732d-8de4-4eb0-bcfa-e7e429710306",
                                                                              "U7qbh20jajtiaW0HHiFvPrNi0I2oZhtDzI_tuS2M3XRBrfRxazUs3Q95_iO7WDZMfU5UwtXo43KdBhU0lVCLKA");
    private ClientCredentials companyClientCredentials = clientCredentials("5b7c2f05-dd20-4c2f-b886-16bc0287ce06",
                                                                           "V9rh6dP7vYvxZSCS4I8C9Z1lfmjDa_Iw5E-9qunenrGwUIkRN9LCv6FVI4Jm6e6Ie3iZj7DlhP-BhEvAZKHF1w");

    @Rule
    public ESClient esClient =
            new ESClient(esUrl, "admin_user", "changeme")
                    .checkRunning(true);


    @Test
    public void authorize_using_client_credentials() throws IOException {
        // Given
        OAuthAuthenticator authenticator = new OAuthClientGrantAuthenticator(tokenEndpoint,
                                                                             companyLabClientCredentials,
                                                                             trustAllHttpClient());
        String bearer = authenticator.acquireAccessToken()
                                     .map(OAuthAuthenticator::toBearer)
                                     .orElseThrow(() -> new IllegalStateException("Not authenticated"));

        // When
        try (Response test = trustAllHttpClient()
                .newCall(new Request.Builder()
                                 .url(esUrl)
                                 .addHeader("Authorization", bearer)
                                 .get()
                                 .build())
                .execute()) {

            // Then
            assertThat(test.isSuccessful()).isTrue();
        }
    }

    @Test
    public void authorize_using_password_credentials() throws IOException {
        // Given
        OAuthAuthenticator authenticator = new PasswordGrantOAuthAuthenticator(tokenEndpoint,
                                                                               userCredentials("p087320", "azerty"),
                                                                               companyLabClientCredentials,
                                                                               trustAllHttpClient());
        String bearer = authenticator.acquireAccessToken()
                                     .map(OAuthAuthenticator::toBearer)
                                     .orElseThrow(() -> new IllegalStateException("Not authenticated"));

        // When
        try (Response test = trustAllHttpClient()
                .newCall(new Request.Builder()
                                 .url(esUrl)
                                 .addHeader("Authorization", bearer)
                                 .get()
                                 .build())
                .execute()) {

            // Then
            assertThat(test.isSuccessful()).isTrue();
        }
    }

    @Test
    public void not_authorized_using_client_credentials() throws IOException {
        // Given
        String bearer = BEARER_PREFIX + "token_too_old";

        // When
        try (Response test = trustAllHttpClient()
                .newCall(new Request.Builder()
                                 .url("http://localhost:9400/")
                                 .addHeader("Authorization", bearer)
                                 .get()
                                 .build())
                .execute()) {

            // Then
            assertThat(test.isSuccessful()).isFalse();
        }
    }

    @Test
    public void try_lab() throws Exception {
        OkHttpClient okHttpClientWithCustomTrust = httpClient(sslContext(null,
                                                                         singleAlternateTrustManagerAsArray(Paths.get("internal-truststore.jks"),
                                                                                                            "changeit")));

        OAuthAuthenticator authenticator = new OAuthClientGrantAuthenticator("https://internal.domain.com:8443/nidp/oauth/nam/token",
                                                                             companyClientCredentials,
                                                                             okHttpClientWithCustomTrust);


        try {
            authenticator.acquireAccessToken();
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }
}

