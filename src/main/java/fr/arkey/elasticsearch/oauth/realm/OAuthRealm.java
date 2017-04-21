package fr.arkey.elasticsearch.oauth.realm;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import com.google.common.collect.ImmutableSet;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.User;
import org.elasticsearch.shield.authc.AuthenticationToken;
import org.elasticsearch.shield.authc.Realm;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.shield.ssl.ClientSSLService;
import org.elasticsearch.transport.TransportMessage;
import org.elasticsearch.watcher.ResourceWatcherService;

import static java.util.concurrent.TimeUnit.SECONDS;
import static java.util.stream.Collectors.joining;

public class OAuthRealm extends Realm<AccessToken> {
    private static final int MAX_TOTAL_CONNECTION = 200;
    private static final long CONNECT_TIMEOUT = 10_000L;
    private static final long SOCKET_TIMEOUT = 10_000L;


    public static final String TYPE = "oauth";
    private static final AccessToken NOT_AN_OAUTH_TOKEN = null;
    private final RefreshableOAuthRoleMapper roleMapper;
    private final ClientSSLService clientSSLService;
    private final String tokenInfoUserField;
    private final String tokenInfoExpiresIn;
    private final TimeUnit tokenInfoExpiresInUnit;
    private final OAuthVerifier oAuthVerifier;
    private final String tokenInfoScopeField;


    public OAuthRealm(RealmConfig config,
                      ResourceWatcherService watcherService,
                      ClientSSLService clientSSLService) {
        super(TYPE, config);

        tokenInfoUserField = config.settings().get("token-info.user.field");
        tokenInfoExpiresIn = config.settings().get("token-info.expires-in.field");
        tokenInfoExpiresInUnit = TimeUnit.valueOf(config.settings()
                                                        .get("token-info.expires-in.field.unit", SECONDS.name())
                                                        .toUpperCase(Locale.getDefault()));
        tokenInfoScopeField = config.settings().get("token-info.scope.field");

        this.roleMapper = new RefreshableOAuthRoleMapper(config,
                                                         watcherService,
                                                         this::expiresAllCacheEntries);
        this.clientSSLService = clientSSLService;
        this.oAuthVerifier = new OAuthVerifier(config);
    }

    private void expiresAllCacheEntries() {
        // TODO expire cache
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
        String token = oauthToken.tokenString;

        // TODO caching
        return oAuthVerifier.performTokenInfoRequest(token)
                            .map(tokenInfo -> {
                                     Integer expires_in_seconds = extractFromMap(tokenInfo, tokenInfoExpiresIn, Integer.class);
                                     String user_id = extractFromMap(tokenInfo, tokenInfoUserField, String.class);
                                     List<String> scopes = extractFromMap(tokenInfo, tokenInfoScopeField, List.class);
                                     if (expires_in_seconds < 2) {
                                         logger.warn("User token for user '{}' expires in {}s", user_id, expires_in_seconds);
                                     }
                                     return new User(user_id, roleMapper.rolesFor(user_id, ImmutableSet.copyOf(scopes)));
                                 }
                            )
                            .orElse(null);
    }

    private <T> T extractFromMap(Map<String, Object> jsonMap, String field, Class<T> type) {
        Object value = jsonMap.get(field);
        if (type.isInstance(value)) {
            return type.cast(value);
        }
        logger.warn("Cannot extract '{}' token info having the following fields '{}', is oauth realm properly configured ?",
                    field,
                    jsonMap.keySet().stream().collect(joining(", ", "[", "]")));
        throw OAuthRealmExceptions.authorizationException();
    }

    /**
     * This method looks for a user that is identified by the given String, not supported by OAuth plugin.
     *
     * @param username the identifier for the user
     * @return {@link User} if found, otherwise <code>null</code>
     */
    @Override
    public User lookupUser(String username) {
        return null;
    }

    @Override
    public boolean userLookupSupported() {
        return false;
    }


}
