package fr.arkey.elasticsearch.oauth.realm.tokeninfo;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import fr.arkey.elasticsearch.oauth.realm.OAuthRealm;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.shield.authc.RealmConfig;
import org.junit.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class MapTokenInfoTest {

    @Test
    public void should_fail_to_deserialize_bad_token_info_json_payload() {

        MapTokenInfo mapTokenInfo = new MapTokenInfo(new RealmConfig("oauth",
                                                                     Settings.builder()
                                                                             .put("type", OAuthRealm.TYPE)
                                                                             .put("token-info.field.user", "user_id")
                                                                             .put("token-info.field.expires-in", "expires_in")
                                                                             .put("token-info.field.scope", "scope")
                                                                             .build(),
                                                                     Settings.builder()
                                                                             .put("path.home", "ignored")
                                                                             .build()));

        assertThatExceptionOfType(ElasticsearchSecurityException.class)
                .isThrownBy(() -> mapTokenInfo.apply(new ByteArrayInputStream("".getBytes(UTF_8))));
        assertThatExceptionOfType(ElasticsearchSecurityException.class)
                .isThrownBy(() -> mapTokenInfo.apply(new ByteArrayInputStream("{}".getBytes(UTF_8))));
        assertThatExceptionOfType(UncheckedIOException.class)
                .isThrownBy(() -> mapTokenInfo.apply(new FailingInputStream()));
        assertThatExceptionOfType(ElasticsearchSecurityException.class)
                .isThrownBy(() -> mapTokenInfo.apply(new ByteArrayInputStream(("{\"user_id\":\"bob\",\"expires_in\":123}").getBytes(UTF_8))));
    }

    @Test
    public void should_deserialize_proper_token_info_json_payload() {

        MapTokenInfo mapTokenInfo = new MapTokenInfo(new RealmConfig("oauth",
                                                                     Settings.builder()
                                                                             .put("type", OAuthRealm.TYPE)
                                                                             .put("token-info.field.user", "user_id")
                                                                             .put("token-info.field.expires-in", "expires_in")
                                                                             .put("token-info.field.scope", "scope")
                                                                             .build(),
                                                                     Settings.builder()
                                                                             .put("path.home", "ignored")
                                                                             .build()));

        assertThat(mapTokenInfo.apply(new ByteArrayInputStream("{\"user_id\":\"bob\",\"expires_in\":987,\"scope\":[]}".getBytes(UTF_8)))).isEqualTo(new TokenInfo("bob", 987, ChronoUnit.SECONDS, Collections.emptySet()));
    }


    private static class FailingInputStream extends InputStream {
        @Override
        public int read() throws IOException {
            throw new IOException("stream broken");
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            throw new IOException("stream broken");
        }
    }
}
