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
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.xpack.security.authc.RealmConfig;
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
                                                                             .build(),
                                                                     new ThreadContext(Settings.EMPTY)));

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
                                                                             .build(),
                                                                     new ThreadContext(Settings.EMPTY)));

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
