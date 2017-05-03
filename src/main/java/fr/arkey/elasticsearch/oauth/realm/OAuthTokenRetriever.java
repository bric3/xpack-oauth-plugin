package fr.arkey.elasticsearch.oauth.realm;

import java.util.Optional;

public interface OAuthTokenRetriever {
    Optional<TokenInfo> getTokenInfo(String accessToken);
}
