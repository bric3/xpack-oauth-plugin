package fr.arkey.elasticsearch.oauth;

import fr.arkey.elasticsearch.oauth.realm.OAuthAuthenticationFailureHandler;
import fr.arkey.elasticsearch.oauth.realm.OAuthRealm;
import fr.arkey.elasticsearch.oauth.realm.OAuthReamFactory;
import fr.arkey.elasticsearch.oauth.realm.support.OAuthRestAction;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestModule;
import org.elasticsearch.shield.authc.AuthenticationModule;

public class OAuthRealmPlugin extends Plugin {
    @Override
    public String name() {
        return "oauth";
    }

    @Override
    public String description() {
        return "simple oauth realm, that can read the 'Authentication: Bearer <token>' header";
    }


    public void onModule(AuthenticationModule authenticationModule) {
        authenticationModule.addCustomRealm(OAuthRealm.TYPE, OAuthReamFactory.class);

        authenticationModule.setAuthenticationFailureHandler(OAuthAuthenticationFailureHandler.class);
    }

    public void onModule(RestModule restModule) {
        restModule.addRestAction(OAuthRestAction.class);
    }
}
