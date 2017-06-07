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

import java.util.Objects;
import java.util.Optional;
import fr.arkey.elasticsearch.oauth.realm.roles.RefreshableOAuthRoleMapper;
import fr.arkey.elasticsearch.oauth.realm.tokeninfo.OAuthTokenRetriever;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.xpack.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.security.authc.Realm;
import org.elasticsearch.xpack.security.authc.RealmConfig;
import org.elasticsearch.xpack.security.user.User;

public class OAuthRealm extends Realm {
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
     * @param threadContext the thread context from where header can be extracted
     * @return the {@link AccessToken} if possible to extractFromMap or <code>null</code> if not an OAuth token
     */
    @Override
    public AccessToken token(ThreadContext threadContext) {
        return Optional.ofNullable(threadContext.getHeader(AccessToken.AUTHORIZATION_HEADER))
                       .filter(AccessToken::isBearer)
                       .map(AccessToken::new)
                       .orElse(NOT_AN_OAUTH_TOKEN);
    }

//    /**
//     * OAuth {@link TransportMessage} authentication is not supported.
//     *
//     * @param transportMessage the message to extractFromMap the token from
//     * @return <code>null</code> / aka not supported
//     */
//    @Override
//    public AccessToken token(TransportMessage<?> transportMessage) {
//        return null;
//    }

    /**
     * Method that handles the actual authentication of the token.
     *
     * This method will only be called if the token is a supported token. The method
     * validates the credentials of the user and if they match, a {@link User} will be
     * returned
     *
     * @param authenticationToken the token to authenticate
     * @return {@link User} if authentication is successful, otherwise <code>null</code>
     */
    @Override
    @Deprecated
    public User authenticate(AuthenticationToken authenticationToken) {
        AccessToken oauthToken = (AccessToken) authenticationToken;
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
    @Deprecated
    public User lookupUser(String ignored) {
        return null;
    }

    @Override
    @Deprecated
    public boolean userLookupSupported() {
        return false;
    }


}
