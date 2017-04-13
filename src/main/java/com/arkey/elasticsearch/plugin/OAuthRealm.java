package com.arkey.elasticsearch.plugin;

import java.util.Map;
import java.util.Optional;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.User;
import org.elasticsearch.shield.authc.AuthenticationToken;
import org.elasticsearch.shield.authc.Realm;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.transport.TransportMessage;

import static com.arkey.elasticsearch.plugin.OAuthToken.AUTHORIZATION_HEADER;

public class OAuthRealm extends Realm<OAuthToken> {
    public static final String TYPE = "oauth";
    private final Map<String, Object> settings;


    public OAuthRealm(RealmConfig config) {
        super(TYPE, config);
        settings = config.settings().getAsStructuredMap();
//        String param = config.settings().get("param");
//        Map<String, Settings> param1 = config.settings().getGroups("param", true);
    }

    /**
     * Indicates whether this realm supports the given token. This realm only support {@link OAuthToken} objects
     * for authentication
     *
     * @param authenticationToken the token to test for support
     * @return true if the token is supported. false otherwise
     */
    @Override
    public boolean supports(AuthenticationToken authenticationToken) {
        return authenticationToken instanceof OAuthToken;
    }

    /**
     * This method will extract a token from the given {@link RestRequest} if possible.
     *
     * This implementation of token extraction looks for two headers, the <code>User</code> header
     * for the username and the <code>Password</code> header for the plaintext password
     *
     * @param restRequest the rest request to extract a token from
     * @return the {@link OAuthToken} if possible to extract or <code>null</code>
     */
    @Override
    public OAuthToken token(RestRequest restRequest) {
        return Optional.ofNullable(restRequest.header(AUTHORIZATION_HEADER))
                       .filter(OAuthToken::isBearer)
                       .map(OAuthToken::new)
                       .orElse(null);
    }

    /**
     * OAuth {@link TransportMessage} authentication is not supported.
     *
     * @param transportMessage the message to extract the token from
     * @return <code>null</code> / aka not supported
     */
    @Override
    public OAuthToken token(TransportMessage<?> transportMessage) {
        return null;
    }

    /**
     * Method that handles the actual authentication of the token.
     *
     * This method will only be called if the token is a supported token. The method
     * validates the credentials of the user and if they match, a {@link User} will be
     * returned
     * @param oauthToken the token to authenticate
     * @return {@link User} if authentication is successful, otherwise <code>null</code>
     */
    @Override
    public User authenticate(OAuthToken oauthToken) {
        // invoke oauth provider
        // cache
        // can return new User("user name", info.roles)
        return null;
    }

    /**
     * This method looks for a user that is identified by the given String.
     *
     * No authentication is performed by this method.
     * If this realm does not support user lookup, then this method will not be called.
     * @param username the identifier for the user
     * @return {@link User} if found, otherwise <code>null</code>
     */
    @Override
    public User lookupUser(String username) {
        // should it be supported ?
        // see below
        return null;
    }

    @Override
    public boolean userLookupSupported() {
        return false;
    }


}
