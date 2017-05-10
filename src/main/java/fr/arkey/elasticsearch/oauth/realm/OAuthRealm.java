package fr.arkey.elasticsearch.oauth.realm;

import java.util.Objects;
import java.util.Optional;
import fr.arkey.elasticsearch.oauth.realm.roles.RefreshableOAuthRoleMapper;
import fr.arkey.elasticsearch.oauth.realm.tokeninfo.OAuthTokenRetriever;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.User;
import org.elasticsearch.shield.authc.AuthenticationToken;
import org.elasticsearch.shield.authc.Realm;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.transport.TransportMessage;

public class OAuthRealm extends Realm<AccessToken> {
    public static final String TYPE = "oauth";
    private static final AccessToken NOT_AN_OAUTH_TOKEN = null;
    private final RefreshableOAuthRoleMapper roleMapper;
    private final OAuthTokenRetriever oAuthTokenRetriever;


    public OAuthRealm(RealmConfig config,
               OAuthTokenRetriever tokenInfoRetriever,
               RefreshableOAuthRoleMapper refreshableOAuthRoleMapper) {
        super(TYPE, Objects.requireNonNull(config));
        this.oAuthTokenRetriever = tokenInfoRetriever;
        this.roleMapper = refreshableOAuthRoleMapper;
    }

    /**
     * Indicates whether this realm supports the given token. This realm only support {@link AccessToken} objects
     * for authentication
     *
     * @param authenticationToken the token to test for support
     * @return true if the token is supported. false otherwise
     */
    @Override
    public boolean supports(AuthenticationToken authenticationToken) {
        return authenticationToken instanceof AccessToken;
    }

    /**
     * This method will extractFromMap a token from the given {@link RestRequest} if possible.
     *
     * This implementation of token extraction looks for two headers, the <code>User</code> header
     * for the username and the <code>Password</code> header for the plaintext password
     *
     * @param restRequest the rest request to extractFromMap a token from
     * @return the {@link AccessToken} if possible to extractFromMap or <code>null</code> if not an OAuth token
     */
    @Override
    public AccessToken token(RestRequest restRequest) {
        return Optional.ofNullable(restRequest.header(AccessToken.AUTHORIZATION_HEADER))
                       .filter(AccessToken::isBearer)
                       .map(AccessToken::new)
                       .orElse(NOT_AN_OAUTH_TOKEN);
    }

    /**
     * OAuth {@link TransportMessage} authentication is not supported.
     *
     * @param transportMessage the message to extractFromMap the token from
     * @return <code>null</code> / aka not supported
     */
    @Override
    public AccessToken token(TransportMessage<?> transportMessage) {
        return null;
    }

    /**
     * Method that handles the actual authentication of the token.
     *
     * This method will only be called if the token is a supported token. The method
     * validates the credentials of the user and if they match, a {@link User} will be
     * returned
     *
     * @param oauthToken the token to authenticate
     * @return {@link User} if authentication is successful, otherwise <code>null</code>
     */
    @Override
    public User authenticate(AccessToken oauthToken) {
        return oAuthTokenRetriever.getTokenInfo(oauthToken.tokenString)
                                  .map(tokenInfo -> new User(tokenInfo.userId,
                                                             roleMapper.rolesFor(tokenInfo.userId,
                                                                                 tokenInfo.scopes)))
                                  .orElse(null);
    }


    /**
     * This method looks for a user that is identified by the given String, not supported
     * by OAuth plugin as user name is not searchable.
     *
     * @param ignored ignored
     * @return <code>null</code>
     */
    @Override
    public User lookupUser(String ignored) {
        return null;
    }

    @Override
    public boolean userLookupSupported() {
        return false;
    }


}
