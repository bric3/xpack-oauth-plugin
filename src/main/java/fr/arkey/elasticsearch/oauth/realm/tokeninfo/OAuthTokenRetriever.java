package fr.arkey.elasticsearch.oauth.realm.tokeninfo;

import java.util.Optional;

/**
 * Contract that says I will return token info for an access token
 */
public interface OAuthTokenRetriever {

    /**
     * Retrieve token info is possible.
     *
     * @param accessToken the access token
     * @return Optional containing the token info for the given access token, or empty optional
     */
    Optional<TokenInfo> getTokenInfo(String accessToken);
}
