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
package fr.arkey.elasticsearch.oauth;

import java.io.IOException;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import fr.arkey.elasticsearch.oauth.tools.ESClient;
import fr.arkey.elasticsearch.oauth.tools.TestResources;
import okhttp3.Credentials;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Rule;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.unauthorized;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static fr.arkey.elasticsearch.oauth.tools.HttpClients.trustAllHttpClient;
import static org.assertj.core.api.Assertions.assertThat;

/*
 * Before,
 *
 * - start the cluster : 'gradle integTestCluster\#start'
 * - or start in debug mode : 'gradle integTestCluster\#start -Pdebug=true'
 *
 * And stop it if necessary with : 'gradle integTestCluster\#stop'
 *
 * Also see task integTestCluster of 'build.gradle'
 */
public class OAuthPluginIT {
    private String esUrl = "http://localhost:" + TestResources.esHttpPort() + "/";

    @Rule
    public ESClient esClient = new ESClient(esUrl, "admin_user", "changeme")
            .checkRunning(true);

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(TestResources.idpPort());


    @Test
    public void should_authorize_using_valid_token() throws IOException {
        // Given
        String valid_access_token = RandomStringUtils.randomAlphanumeric(70);
        stubFor(get(urlEqualTo("/nidp/oauth/nam/tokeninfo"))
                        .withHeader("Accept", equalTo("application/json"))
                        .withHeader("Authorization", equalTo("Bearer " + valid_access_token))
                        .withHeader("Cache-Control", equalTo("no-cache"))
                        .willReturn(okJson("{\"user_id\":\"bob\",\"expires_in\":" + 200 + ",\"scope\":[]}")
                                            .withHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
                                            .withHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
                                            .withHeader("Strict-Transport-Security", "max-age=31536000")
                        )
        );

        // When
        try (Response test = trustAllHttpClient()
                .newCall(new Request.Builder()
                                 .url(esUrl)
                                 .addHeader("Authorization", "Bearer " + valid_access_token)
                                 .get()
                                 .build())
                .execute()) {

            // Then
            assertThat(test.isSuccessful()).isTrue();
        }
    }

    @Test
    public void should_forbid_using_valid_token_but_role_forbidden() throws IOException {
        // Given
        String valid_access_token = RandomStringUtils.randomAlphanumeric(70);
        stubFor(get(urlEqualTo("/nidp/oauth/nam/tokeninfo"))
                        .withHeader("Accept", equalTo("application/json"))
                        .withHeader("Authorization", equalTo("Bearer " + valid_access_token))
                        .withHeader("Cache-Control", equalTo("no-cache"))
                        .willReturn(okJson("{\"user_id\":\"alice\",\"expires_in\":" + 200 + ",\"scope\":[]}")
                                            .withHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
                                            .withHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
                                            .withHeader("Strict-Transport-Security", "max-age=31536000")
                        )
        );

        // When
        try (Response test = trustAllHttpClient()
                .newCall(new Request.Builder()
                                 .url(esUrl)
                                 .addHeader("Authorization", "Bearer " + valid_access_token)
                                 .get()
                                 .build())
                .execute()) {

            // Then
            assertThat(test.isSuccessful()).isFalse();
            assertThat(test.body().string()).contains("\"type\":\"security_exception\"",
                                                      "\"reason\":\"action [cluster:monitor/main] is unauthorized for user [alice]\"");
        }
    }

    @Test
    public void should_authorize_using_same_token() throws IOException {
        String valid_access_token = RandomStringUtils.randomAlphanumeric(70);
        // Given
        stubFor(get(urlEqualTo("/nidp/oauth/nam/tokeninfo"))
                        .withHeader("Accept", equalTo("application/json"))
                        .withHeader("Authorization", equalTo("Bearer " + valid_access_token))
                        .withHeader("Cache-Control", equalTo("no-cache"))
                        .willReturn(okJson("{\"user_id\":\"bob\",\"expires_in\":" + 200 + ",\"scope\":[]}")
                                            .withHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
                                            .withHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
                                            .withHeader("Strict-Transport-Security", "max-age=31536000")
                        )
        );

        // first
        try (Response test = trustAllHttpClient()
                .newCall(new Request.Builder()
                                 .url(esUrl)
                                 .addHeader("Authorization", "Bearer " + valid_access_token)
                                 .get()
                                 .build())
                .execute()) {
            noop(test);
        }


        // When
        try (Response test = trustAllHttpClient()
                .newCall(new Request.Builder()
                                 .url(esUrl)
                                 .addHeader("Authorization", "Bearer " + valid_access_token)
                                 .get()
                                 .build())
                .execute()) {

            // Then
            assertThat(test.isSuccessful()).isTrue();
            verify(1, getRequestedFor(urlEqualTo("/nidp/oauth/nam/tokeninfo")));
        }
    }

    @Test
    public void not_authorized_using_unknown_token() throws IOException {
        // Given
        stubFor(get(urlEqualTo("/nidp/oauth/nam/tokeninfo"))
                        .withHeader("Accept", equalTo("application/json"))
                        .withHeader("Authorization", equalTo("Bearer " + "an_expired_access_token"))
                        .withHeader("Cache-Control", equalTo("no-cache"))
                        .willReturn(unauthorized()
                                            .withHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
                                            .withHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
                                            .withHeader("Strict-Transport-Security", "max-age=31536000")
                                            .withHeader("WWW-Authenticate", "error=OAuth bearer token required. Token has expired")
                                            .withBody("{\"error\":\"oauth authentication required\"}")
                        )
        );

        // When
        try (Response test = trustAllHttpClient()
                .newCall(new Request.Builder()
                                 .url("http://localhost:9400/")
                                 .addHeader("Authorization", "Bearer " + "an_expired_access_token")
                                 .get()
                                 .build())
                .execute()) {

            // Then
            assertThat(test.isSuccessful()).isFalse();
            assertThat(test.code()).isEqualTo(401);
            assertThat(test.headers().get("WWW-Authenticate")).isEqualTo("Bearer realm=\"security\" charset=\"UTF-8\" delegateError=\"error=OAuth bearer token required. Token has expired\"");
        }
    }

    @Test
    public void not_authorized_failure_using_basic_auth_header_refer_to_basic_realm() throws IOException {
        // Given

        // When
        try (Response test = trustAllHttpClient()
                .newCall(new Request.Builder()
                                 .url("http://localhost:9400/")
                                 .addHeader("Authorization", Credentials.basic("bad_user", "bad_password"))
                                 .get()
                                 .build())
                .execute()) {

            // Then
            assertThat(test.isSuccessful()).isFalse();
            assertThat(test.headers().get("WWW-Authenticate")).isEqualTo("Basic realm=\"security\" charset=\"UTF-8\"");
        }
    }

    private void noop(Object wormhole) {
        // stupid method to avoid compile failure, as it is configured with -Werror
    }
}

