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
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.StreamSupport;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import fr.arkey.elasticsearch.oauth.realm.OAuthRealm;
import okhttp3.HttpUrl;
import org.assertj.core.api.Condition;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.xpack.security.authc.RealmConfig;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mockito;

import static java.time.temporal.ChronoUnit.SECONDS;
import static java.util.stream.Collectors.toSet;
import static com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.unauthorized;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.from;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

public class HttpOAuthTokenRetrieverTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort());
    private HttpOAuthTokenRetriever tokenRetriever;


    @SuppressWarnings("unchecked")
    @Before
    public void initialize_token_info_retriever() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper().disable(FAIL_ON_UNKNOWN_PROPERTIES);
        tokenRetriever = new HttpOAuthTokenRetriever(
                new RealmConfig("oauth",
                                Settings.builder()
                                        .put("type", OAuthRealm.TYPE)
                                        .put("token-info.url", HttpUrl.parse("http://localhost:80/token-info")
                                                                      .newBuilder()
                                                                      .port(wireMockRule.port())
                                                                      .build()
                                                                      .toString())
                                        .build(),
                                Settings.builder()
                                        .put("path.home", "ignored")
                                        .build(),
                                new ThreadContext(Settings.EMPTY)),
                contentIS -> {
                    try (InputStream is = contentIS) {
                        JsonNode jsonNode = objectMapper.readTree(is);
                        return new TokenInfo(jsonNode.get("user_id").asText(),
                                             jsonNode.get("expires_in").asInt(), SECONDS,
                                             StreamSupport.stream(jsonNode.get("scope").spliterator(), false)
                                                          .map(JsonNode::asText)
                                                          .collect(toSet()));
                    } catch (IOException ioe) {
                        throw new UncheckedIOException(ioe);
                    }
                }
        );
    }

    @Test
    public void should_access_token_information_when_bearer_is_valid() {
        stubFor(get(urlEqualTo("/token-info"))
                        .withHeader("Accept", equalTo("application/json"))
                        .withHeader("Authorization", equalTo("Bearer " + "a_valid_access_token"))
                        .withHeader("Cache-Control", equalTo("no-cache"))
                        .willReturn(okJson(tokenInfoPayload("bob", 123))
                                            .withHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
                                            .withHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
                                            .withHeader("Strict-Transport-Security", "max-age=31536000")
                        )
        );


        Optional<TokenInfo> tokenInfo = tokenRetriever.getTokenInfo("a_valid_access_token");

        assertThat(tokenInfo).isNotEmpty();
        assertThat(tokenInfo.get()).returns("bob", from(t -> t.userId));
    }

    @Test
    public void should_not_access_token_information_when_bearer_has_expired() {
        stubFor(get(urlEqualTo("/token-info"))
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

        assertThatExceptionOfType(ElasticsearchSecurityException.class).isThrownBy(() -> tokenRetriever.getTokenInfo("an_expired_access_token"))
                                                                       .has(headerContaining("WWW-Authenticate",
                                                                                             "delegateError=\"error=OAuth bearer token required. Token has expired\""))
                                                                       .has(headerContaining("WWW-Authenticate",
                                                                                             "Bearer realm=\"shield\" charset=\"UTF-8\""));
    }


    @Test
    public void should_fail_authentication_when_idp_tokeninfo_body_cannot_be_read() {
        @SuppressWarnings("unchecked")
        Function<InputStream, TokenInfo> tokenBodyReader = Mockito.mock(Function.class);
        tokenRetriever = new HttpOAuthTokenRetriever(
                new RealmConfig("oauth",
                                Settings.builder()
                                        .put("type", OAuthRealm.TYPE)
                                        .put("token-info.url", HttpUrl.parse("http://localhost:80/token-info")
                                                                      .newBuilder()
                                                                      .port(wireMockRule.port())
                                                                      .build()
                                                                      .toString())
                                        .build(),
                                Settings.builder()
                                        .put("path.home", "ignored")
                                        .build(),
                                new ThreadContext(Settings.EMPTY)),
                tokenBodyReader
        );

        stubFor(get(urlEqualTo("/token-info"))
                        .withHeader("Accept", equalTo("application/json"))
                        .withHeader("Authorization", equalTo("Bearer " + "an_expired_access_token"))
                        .withHeader("Cache-Control", equalTo("no-cache"))
                        .willReturn(okJson(tokenInfoPayload("bob", 123))
                                            .withHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
                                            .withHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
                                            .withHeader("Strict-Transport-Security", "max-age=31536000")
                        )
        );
        given(tokenBodyReader.apply(any())).willThrow(new UncheckedIOException(new IOException()));

        assertThatExceptionOfType(ElasticsearchSecurityException.class).isThrownBy(() -> tokenRetriever.getTokenInfo("an_expired_access_token"))
                                                                       .has(headerContaining("WWW-Authenticate",
                                                                                             "Bearer realm=\"shield\" charset=\"UTF-8\""));
    }


    private String tokenInfoPayload(String user, int expiresIn) {
        return "{" +
               "\"user_id\":\"" +
               user +
               "\"," +
               "\"expires_in\":" +
               expiresIn +
               "," +
               "\"scope\":[]" +
               "}";
    }

    private Condition<ElasticsearchSecurityException> headerContaining(final String header, final String valueToBeContainted) {
        return new Condition<ElasticsearchSecurityException>() {
            @Override
            public boolean matches(ElasticsearchSecurityException value) {
                return value.getHeader(header)
                            .stream()
                            .anyMatch(hv -> hv.contains(valueToBeContainted));
            }
        };
    }
}
