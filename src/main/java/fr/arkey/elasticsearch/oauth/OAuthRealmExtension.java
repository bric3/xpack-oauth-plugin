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

import java.util.Collection;
import java.util.Map;
import fr.arkey.elasticsearch.oauth.realm.AccessToken;
import fr.arkey.elasticsearch.oauth.realm.OAuthAuthenticationFailureHandler;
import fr.arkey.elasticsearch.oauth.realm.OAuthRealm;
import fr.arkey.elasticsearch.oauth.realm.OAuthReamFactory;
import org.elasticsearch.common.collect.MapBuilder;
import org.elasticsearch.watcher.ResourceWatcherService;
import org.elasticsearch.xpack.extensions.XPackExtension;
import org.elasticsearch.xpack.security.authc.AuthenticationFailureHandler;
import org.elasticsearch.xpack.security.authc.Realm;

import static java.util.Collections.singleton;

public class OAuthRealmExtension extends XPackExtension {
    @Override
    public String name() {
        return "oauth";
    }

    @Override
    public String description() {
        return "simple oauth realm, that can read the 'Authentication: Bearer <token>' header";
    }

    /**
     * Returns a collection of header names that will be used by this extension. This is necessary to ensure the headers are copied from
     * the incoming request and made available to your realm(s).
     */
    @Override
    public Collection<String> getRestHeaders() {
        return singleton(AccessToken.AUTHORIZATION_HEADER);
    }


    /**
     * Returns a map of the custom realms provided by this extension. The first parameter is the string representation of the realm type;
     * this is the value that is specified when declaring a realm in the settings. Note, the realm type cannot be one of the types
     * defined by X-Pack. In order to avoid a conflict, you may wish to use some prefix to your realm types.
     *
     * The second parameter is an instance of the {@link Realm.Factory} implementation. This factory class will be used to create realms of
     * this type that are defined in the elasticsearch settings.
     */
    @Override
    public Map<String, Realm.Factory> getRealms(ResourceWatcherService resourceWatcherService) {
        return new MapBuilder<String, Realm.Factory>()
                .put(OAuthRealm.TYPE, new OAuthReamFactory(resourceWatcherService))
                .immutableMap();
    }

    /**
     * Returns the custom authentication failure handler. Note only one implementation and instance of a failure handler can
     * exist. There is a default implementation, {@link org.elasticsearch.xpack.security.authc.DefaultAuthenticationFailureHandler} that
     * can be extended where appropriate. If no changes are needed to the default implementation, then there is no need to override this
     * method.
     */
    @Override
    public AuthenticationFailureHandler getAuthenticationFailureHandler() {
        return new OAuthAuthenticationFailureHandler();
    }

//    public void onModule(AuthenticationModule authenticationModule) {
//        authenticationModule.addCustomRealm(OAuthRealm.TYPE, OAuthReamFactory.class);
//
//        authenticationModule.setAuthenticationFailureHandler(OAuthAuthenticationFailureHandler.class);
//    }
//
//    public void onModule(RestModule restModule) {
//        restModule.addRestAction(OAuthRestAction.class);
//    }
}
