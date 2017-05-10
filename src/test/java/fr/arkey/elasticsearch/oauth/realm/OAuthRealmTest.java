package fr.arkey.elasticsearch.oauth.realm;

import java.util.Optional;
import fr.arkey.elasticsearch.oauth.realm.roles.RefreshableOAuthRoleMapper;
import fr.arkey.elasticsearch.oauth.realm.tokeninfo.OAuthTokenRetriever;
import fr.arkey.elasticsearch.oauth.realm.tokeninfo.TokenInfo;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.shield.User;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.shield.authc.support.SecuredString;
import org.elasticsearch.shield.authc.support.UsernamePasswordToken;
import org.elasticsearch.test.rest.FakeRestRequest;
import org.elasticsearch.transport.TransportMessage;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import static java.time.temporal.ChronoUnit.MINUTES;
import static java.util.Collections.emptyMap;
import static java.util.Collections.emptySet;
import static java.util.Collections.singletonMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;

public class OAuthRealmTest {
    @Rule
    public MockitoRule mrulez = MockitoJUnit.rule();

    @Mock
    private OAuthTokenRetriever tokenInfoRetriever;
    @Mock
    private RefreshableOAuthRoleMapper oAuthRoleMapper;

    private OAuthRealm oAuthRealm;

    @Test
    public void should_try_to_authenticate_using_token_info_retriever_and_role_mapper() {
        given(tokenInfoRetriever.getTokenInfo("the_access_token_to_authenticate")).willReturn(Optional.of(new TokenInfo("bob", 12, MINUTES, emptySet())));
        given(oAuthRoleMapper.rolesFor("bob", emptySet())).willReturn(new String[] { "role1", "role2"});

        assertThat(oAuthRealm.authenticate(new AccessToken("Bearer the_access_token_to_authenticate"))).isEqualTo(new User("bob", "role1", "role2"));
    }

    @Test
    public void should_return_null_for_transport_message_aka_not_supported() {
        assertThat(oAuthRealm.token(new DummyMessageTransportMessage())).isNull();
    }

    @Test
    public void should_return_null_for_rest_request_if_no_bearer_authorization_header() {
        assertThat(oAuthRealm.token(new FakeRestRequest())).isNull();
        assertThat(oAuthRealm.token(new FakeRestRequest(singletonMap("Authorization", "Basic YWRtaW46YWRtaW5fcHdk"),
                                                        emptyMap()))).isNull();
    }

    @Test
    public void should_return_AccessToken_for_rest_request_with_bearer_authorization_header() {
        assertThat(oAuthRealm.token(new FakeRestRequest())).isNull();
        assertThat(oAuthRealm.token(new FakeRestRequest(singletonMap("Authorization", "Bearer an_access_token"),
                                                        emptyMap()))).isEqualTo(new AccessToken("Bearer an_access_token"));
    }

    @Test
    public void should_not_support_user_lookup() {
        assertThat(oAuthRealm.lookupUser("whatever")).isNull();
        assertThat(oAuthRealm.userLookupSupported()).isFalse();
    }

    @Test
    public void should_support_access_token_only() {
        assertThat(oAuthRealm.supports(new AccessToken("Bearer an_access_token"))).isTrue();
        assertThat(oAuthRealm.supports(new UsernamePasswordToken("a user name", new SecuredString(new char[0])))).isFalse();
    }

    @Before
    public void initialize_realm() {
        oAuthRealm = new OAuthRealm(
                new RealmConfig("oauth",
                                Settings.builder()
                                        .put("type", OAuthRealm.TYPE)
                                        .build(),
                                Settings.builder()
                                        .put("path.home", "ignored")
                                        .build()),
                tokenInfoRetriever,
                oAuthRoleMapper);
    }

    private static class DummyMessageTransportMessage extends TransportMessage<DummyMessageTransportMessage> {
    }
}
