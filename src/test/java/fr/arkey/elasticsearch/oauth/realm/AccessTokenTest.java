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

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.rest.RestStatus;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class AccessTokenTest {

    @Test
    public void should_verify_bearer() {
        assertThat(AccessToken.isBearer("Bearer yes_it_is")).isTrue();
        assertThat(AccessToken.isBearer("Bearers nope")).isFalse();
        assertThat(AccessToken.isBearer("Bearer_nope")).isFalse();
        assertThat(AccessToken.isBearer("Bearernope")).isFalse();
        assertThat(AccessToken.isBearer("Basic jsdlfs")).isFalse();
    }

    @Test
    public void can_extract_access_token() {
        assertThat(new AccessToken("Bearer access_token").credentials()).isEqualTo("access_token");
        assertThatThrownBy(() -> new AccessToken("Beareraccess_token"))
                .isInstanceOf(ElasticsearchSecurityException.class)
                .extracting("status")
                .contains(RestStatus.UNAUTHORIZED);

    }
}
