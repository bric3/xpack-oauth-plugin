package fr.arkey.elasticsearch.oauth;

import fr.arkey.elasticsearch.oauth.realm.OAuthAuthenticationFailureHandler;
import fr.arkey.elasticsearch.oauth.realm.OAuthReamFactory;
import fr.arkey.elasticsearch.oauth.realm.support.OAuthRestAction;
import org.elasticsearch.rest.RestModule;
import org.elasticsearch.shield.authc.AuthenticationModule;
import org.junit.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class OAuthRealmPluginTest {

    @Test
    public void should_register_oauth_realm() {
        AuthenticationModule authenticationModule = mock(AuthenticationModule.class);

        new OAuthRealmPlugin().onModule(authenticationModule);

        verify(authenticationModule).addCustomRealm("oauth", OAuthReamFactory.class);
        verify(authenticationModule).setAuthenticationFailureHandler(OAuthAuthenticationFailureHandler.class);
        verifyNoMoreInteractions(authenticationModule);
    }

    @Test
    public void should_register_simple_rest_action_for_oauth_realm() {
        RestModule restModule = mock(RestModule.class);

        new OAuthRealmPlugin().onModule(restModule);

        verify(restModule).addRestAction(OAuthRestAction.class);
        verifyNoMoreInteractions(restModule);
    }


}
