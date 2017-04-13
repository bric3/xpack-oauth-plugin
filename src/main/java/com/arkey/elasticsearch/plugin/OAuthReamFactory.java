package com.arkey.elasticsearch.plugin;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.shield.ShieldSettingsFilter;
import org.elasticsearch.shield.authc.Realm;
import org.elasticsearch.shield.authc.RealmConfig;

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

    @Inject
    public OAuthReamFactory(ShieldSettingsFilter settingsFilter) {
        super(OAuthRealm.TYPE, false);
        this.settingsFilter = settingsFilter;
    }

    /**
     * Create a {@link OAuthRealm} based on the given configuration
     * @param realmConfig the configuration to create the realm with
     * @return the realm
     */
    @Override
    public OAuthRealm create(RealmConfig realmConfig) {
        // filter out all of the user information for the realm that is being created
        settingsFilter.filterOut("shield.authc.realms." + realmConfig.name() + ".*");
        return new OAuthRealm(realmConfig);
    }

    /**
     * Method that can be called to create a realm without configuration. This is called for internal realms only and
     * can simply return <code>null</code>
     * @param name the name of the realm
     * @return <code>null</code>
     */
    @Override
    public OAuthRealm createDefault(String name) {
        return null;
    }
}
