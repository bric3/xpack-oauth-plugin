package fr.arkey.elasticsearch.oauth.realm;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheStats;
import org.elasticsearch.shield.authc.RealmConfig;

import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * A simple token-info cache decorating a delegate token retriever.
 *
 * As token are cached this class asks for a way to determine if token are expired.
 */
public class CachingOAuthTokenRetriever implements OAuthTokenRetriever {

    public static final int DEFAULT_MAX_CACHE_SIZE = 20_000;
    public static final int DEFAULT_ENTRY_EXPIRATION_IN_SECONDS = 300;
    private final Cache<String, TokenInfo> tokensCache;
    private OAuthTokenRetriever delegate;
    private Predicate<TokenInfo> tokenExpirationPredicate;

    public CachingOAuthTokenRetriever(RealmConfig config,
                                      OAuthTokenRetriever delegate,
                                      Predicate<TokenInfo> tokenExpirationPredicate) {
        Objects.requireNonNull(config);
        this.delegate = Objects.requireNonNull(delegate);
        this.tokenExpirationPredicate = Objects.requireNonNull(tokenExpirationPredicate);

        tokensCache = CacheBuilder.newBuilder()
                                  .maximumSize(config.settings()
                                                     .getAsInt("token-info.cache.max-size",
                                                               DEFAULT_MAX_CACHE_SIZE))
                                  .expireAfterWrite(config.settings()
                                                          .getAsInt("token-info.cache.expire-in-seconds",
                                                                    DEFAULT_ENTRY_EXPIRATION_IN_SECONDS),
                                                    SECONDS)
                                  .recordStats()
                                  .build();
    }

    /**
     * Get token info and caches it for the configured expiration time.
     *
     * @param accessToken the access token string
     * @return An optional with or without the token.
     */
    @Override
    public Optional<TokenInfo> getTokenInfo(String accessToken) {
        TokenInfo tokenInfo = tokensCache.asMap()
                                         .computeIfAbsent(accessToken,
                                                          accessTokenToFetch -> delegate.getTokenInfo(accessTokenToFetch)
                                                                                        .orElse(null));

        if (tokenInfo == null) {
            return Optional.empty();
        }

        if (tokenExpirationPredicate.test(tokenInfo)) {
            tokensCache.asMap().remove(accessToken, tokenInfo);
            return Optional.empty();
        }

        return Optional.of(tokenInfo);
    }

    /**
     * Clear all cached token info entries.
     */
    public void expiresAll() {
        tokensCache.invalidateAll();
    }

    /**
     * Could be useful to expose on the custom rest endpoint, unknown how to do it at the moment;
     *
     * @return cache statistics.
     */
    public CacheStats stats() {
        return tokensCache.stats();
    }

}
