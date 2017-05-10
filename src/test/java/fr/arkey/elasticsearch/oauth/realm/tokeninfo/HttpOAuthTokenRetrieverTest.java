package fr.arkey.elasticsearch.oauth.realm.tokeninfo;

import java.util.List;
import java.util.Optional;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.common.collect.ImmutableSet;
import fr.arkey.elasticsearch.oauth.realm.OAuthRealm;
import okhttp3.HttpUrl;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.shield.authc.RealmConfig;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import static java.time.temporal.ChronoUnit.SECONDS;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.unauthorized;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.from;

public class HttpOAuthTokenRetrieverTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort());
    private HttpOAuthTokenRetriever tokenRetriever;


    @SuppressWarnings("unchecked")
    @Before
    public void initialize_token_info_retriever() throws Exception {
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
                                        .build()),
                map -> new TokenInfo((String) map.get("user_id"),
                                     (Integer) map.get("expires_in"), SECONDS,
                                     ImmutableSet.copyOf((List) map.get("scope")))
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

        assertThat(tokenRetriever.getTokenInfo("an_expired_access_token")).isEmpty();
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
}
