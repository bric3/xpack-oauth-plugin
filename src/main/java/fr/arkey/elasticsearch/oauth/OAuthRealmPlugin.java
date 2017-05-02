package fr.arkey.elasticsearch.oauth;

import fr.arkey.elasticsearch.oauth.realm.OAuthRealm;
import fr.arkey.elasticsearch.oauth.realm.OAuthReamFactory;
import fr.arkey.elasticsearch.oauth.realm.OAuthRestAction;
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
        return "simple oauth realm, that can read the 'Authentication: Bearer <token>' header, " +
               "and deal with it ?";
    }


    public void onModule(AuthenticationModule authenticationModule) {
//        /*
//         * Registers the custom realm. The first parameter is the String representation of a realm type; this is the
//         * value that is specified when declaring a realm in the settings. Note, the realm type cannot be one of the
//         * types defined by Shield. In order to avoid a conflict, you may wish to use some prefix to your realm types.
//         *
//         * The second parameter is the Realm.Factory implementation. This factory class will be used to create any realm
//         * of this type that is defined in the elasticsearch settings.
//         */
        authenticationModule.addCustomRealm(OAuthRealm.TYPE, OAuthReamFactory.class);

//        // register the custom caching realm with a separate call
//        authenticationModule.addCustomRealm(CustomCachingRealm.TYPE, CustomCachingRealmFactory.class);
//
//        /*
//         * Register the custom authentication failure handler. Note only one implementation of a failure handler can
//         * exist and there is a default implementation that can be extended where appropriate. If no changes are needed
//         * to the default implementation, then a custom failure handler does not need to be provided.
//         */
//        authenticationModule.setAuthenticationFailureHandler(CustomAuthenticationFailureHandler.class);
    }

    public void onModule(RestModule restModule) {
        restModule.addRestAction(OAuthRestAction.class);
    }
}
