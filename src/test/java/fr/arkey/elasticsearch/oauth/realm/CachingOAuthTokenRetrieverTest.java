package fr.arkey.elasticsearch.oauth.realm;

import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.shield.authc.RealmConfig;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import static java.time.temporal.ChronoUnit.MILLIS;
import static java.time.temporal.ChronoUnit.MINUTES;
import static java.time.temporal.ChronoUnit.SECONDS;
import static java.util.Collections.emptySet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class CachingOAuthTokenRetrieverTest {
    @Rule
    public MockitoRule mockitoRule = MockitoJUnit.rule();

    @Mock
    private OAuthTokenRetriever delegateRetriever;

    @Test
    public void should_ensure_dependencies_are_not_null() {
        assertThatThrownBy(() -> new CachingOAuthTokenRetriever(null, delegateRetriever, v -> false)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new CachingOAuthTokenRetriever(realmConfig(), null, v -> false)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new CachingOAuthTokenRetriever(realmConfig(), delegateRetriever, null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    public void should_delegate_token_info_request_when_not_in_cache() {
        CachingOAuthTokenRetriever retriever = new CachingOAuthTokenRetriever(realmConfig(), delegateRetriever, tokenInfo -> false);

        given(delegateRetriever.getTokenInfo("a valid access token")).willReturn(Optional.of(new TokenInfo("bob", 12, MINUTES, emptySet())));

        assertThat(retriever.getTokenInfo("a valid access token")).contains(new TokenInfo("bob", 12, MINUTES, emptySet()));
    }

    @Test
    public void should_use_cache_when_access_token_has_been_used() {
        CachingOAuthTokenRetriever retriever = new CachingOAuthTokenRetriever(realmConfig(), delegateRetriever, tokenInfo -> false);
        given(delegateRetriever.getTokenInfo("a valid access token")).willReturn(Optional.of(new TokenInfo("bob", 12, MINUTES, emptySet())));

        retriever.getTokenInfo("a valid access token");
        retriever.getTokenInfo("a valid access token");

        assertThat(retriever.getTokenInfo("a valid access token")).contains(new TokenInfo("bob", 12, MINUTES, emptySet()));

        verify(delegateRetriever, times(1)).getTokenInfo("a valid access token");
    }

    @Test
    public void should_verify_expiration() throws InterruptedException {
        CachingOAuthTokenRetriever retriever = new CachingOAuthTokenRetriever(realmConfig(), delegateRetriever, tokenInfo -> true);
        given(delegateRetriever.getTokenInfo("a valid access token")).willReturn(Optional.of(new TokenInfo("bob", 1, MILLIS, emptySet())));

        assertThat(retriever.getTokenInfo("a valid access token")).isEmpty();
    }

    @Test
    public void should_verify_expiration_with_token_values() throws InterruptedException {
        CachingOAuthTokenRetriever retriever = new CachingOAuthTokenRetriever(realmConfig(), delegateRetriever, TokenInfo::isExpired);
        given(delegateRetriever.getTokenInfo("a valid access token")).willReturn(Optional.of(new TokenInfo("bob", 1, SECONDS, emptySet())));

        assertThat(retriever.getTokenInfo("a valid access token")).isNotEmpty();

        TimeUnit.SECONDS.sleep(1);

        assertThat(retriever.getTokenInfo("a valid access token")).isEmpty();
    }

    @Test
    public void should_expire_cache_entries() throws InterruptedException {
        CachingOAuthTokenRetriever retriever = new CachingOAuthTokenRetriever(realmConfig(), delegateRetriever, TokenInfo::isExpired);
        given(delegateRetriever.getTokenInfo(any())).willReturn(Optional.of(new TokenInfo("bob", 12, MINUTES, emptySet())));

        assertThat(retriever.getTokenInfo("a valid access token")).isNotEmpty();

        TimeUnit.SECONDS.sleep(3);

        assertThat(retriever.getTokenInfo("a valid access token")).isNotEmpty();

        verify(delegateRetriever, times(2)).getTokenInfo("a valid access token");
    }

    private RealmConfig realmConfig() {
        return new RealmConfig("mapper",
                               Settings.builder()
                                       .put("type", OAuthRealm.TYPE)
                                       .put("token-info.cache.max-size", "1")
                                       .put("token-info.cache.expire-in-seconds", "2")
                                       .build(),
                               Settings.builder()
                                       .put("path.home", "ignored")
                                       .build());
    }
}
