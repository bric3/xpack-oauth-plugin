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
package fr.arkey.elasticsearch.oauth.realm;

import fr.arkey.elasticsearch.oauth.realm.roles.RefreshableOAuthRoleMapper;
import fr.arkey.elasticsearch.oauth.realm.tokeninfo.CachingOAuthTokenRetriever;
import fr.arkey.elasticsearch.oauth.realm.tokeninfo.HttpOAuthTokenRetriever;
import fr.arkey.elasticsearch.oauth.realm.tokeninfo.MapTokenInfo;
import fr.arkey.elasticsearch.oauth.realm.tokeninfo.TokenInfo;
import org.elasticsearch.watcher.ResourceWatcherService;
import org.elasticsearch.xpack.security.authc.Realm;
import org.elasticsearch.xpack.security.authc.RealmConfig;

/**
 * The factory class for the {@link OAuthRealm}. This factory class is responsible for properly constructing the realm
 * when called by the Shield framework.
 */
public class OAuthReamFactory implements Realm.Factory {
    /*
     * The {@link ShieldSettingsFilter} is filter that allows for the settings shown in the elasticsearch REST APIs to be
     * filtered. This is useful when there is sensitive information that should not be retrieved via HTTP requests
     */
//    private final SettingsFilter settingsFilter;
    private ResourceWatcherService watcherService;

    public OAuthReamFactory(ResourceWatcherService resourceWatcherService) {
        watcherService = resourceWatcherService;
    }

//    @Inject
//    public OAuthReamFactory(ShieldSettingsFilter settingsFilter,
//                            ResourceWatcherService watcherService) {
//        super(OAuthRealm.TYPE, false);
//        this.settingsFilter = settingsFilter;
//        this.watcherService = watcherService;
//    }

    /**
     * Create a {@link OAuthRealm} based on the given configuration
     *
     * @param realmConfig the configuration to create the realm with
     * @return the realm
     */
    @Override
    public OAuthRealm create(RealmConfig realmConfig) {
//        // filter out all of the user information for the realm that is being created
//        settingsFilter.filterOut("shield.authc.realms." + realmConfig.name() + ".*");

        // avoiding Guice injection since it will disappear in ES 5
        CachingOAuthTokenRetriever cachingOAuthTokenRetriever =
                new CachingOAuthTokenRetriever(
                        realmConfig,
                        new HttpOAuthTokenRetriever(realmConfig,
                                                    new MapTokenInfo(realmConfig)),
                        TokenInfo::isExpired
                );

        RefreshableOAuthRoleMapper roleMapper = new RefreshableOAuthRoleMapper(realmConfig,
                                                                               watcherService,
                                                                               cachingOAuthTokenRetriever::expiresAll);
        return new OAuthRealm(realmConfig,
                              cachingOAuthTokenRetriever,
                              roleMapper);
    }

//    /**
//     * Method that can be called to create a realm without configuration. This is called for internal realms only and
//     * can simply return <code>null</code>
//     *
//     * @param name the name of the realm
//     * @return <code>null</code>
//     */
//    @Override
//    public OAuthRealm createDefault(String name) {
//        return null;
//    }

}
