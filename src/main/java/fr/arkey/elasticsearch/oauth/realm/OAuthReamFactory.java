package fr.arkey.elasticsearch.oauth.realm;

import fr.arkey.elasticsearch.oauth.realm.roles.RefreshableOAuthRoleMapper;
import fr.arkey.elasticsearch.oauth.realm.tokeninfo.CachingOAuthTokenRetriever;
import fr.arkey.elasticsearch.oauth.realm.tokeninfo.HttpOAuthTokenRetriever;
import fr.arkey.elasticsearch.oauth.realm.tokeninfo.MapTokenInfo;
import fr.arkey.elasticsearch.oauth.realm.tokeninfo.TokenInfo;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.shield.ShieldSettingsFilter;
import org.elasticsearch.shield.authc.Realm;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.watcher.ResourceWatcherService;

/**
 * The factory class for the {@link OAuthRealm}. This factory class is responsible for properly constructing the realm
 * when called by the Shield framework.
 */
public class OAuthReamFactory extends Realm.Factory<OAuthRealm> {
    /*
     * The {@link ShieldSettingsFilter} is filter that allows for the settings shown in the elasticsearch REST APIs to be
     * filtered. This is useful when there is sensitive information that should not be retrieved via HTTP requests
     */
    private final ShieldSettingsFilter settingsFilter;
    private ResourceWatcherService watcherService;

    @Inject
    public OAuthReamFactory(ShieldSettingsFilter settingsFilter,
                            ResourceWatcherService watcherService) {
        super(OAuthRealm.TYPE, false);
        this.settingsFilter = settingsFilter;
        this.watcherService = watcherService;
    }

    /**
     * Create a {@link OAuthRealm} based on the given configuration
     *
     * @param realmConfig the configuration to create the realm with
     * @return the realm
     */
    @Override
    public OAuthRealm create(RealmConfig realmConfig) {
        // filter out all of the user information for the realm that is being created
        settingsFilter.filterOut("shield.authc.realms." + realmConfig.name() + ".*");

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

    /**
     * Method that can be called to create a realm without configuration. This is called for internal realms only and
     * can simply return <code>null</code>
     *
     * @param name the name of the realm
     * @return <code>null</code>
     */
    @Override
    public OAuthRealm createDefault(String name) {
        return null;
    }

}
