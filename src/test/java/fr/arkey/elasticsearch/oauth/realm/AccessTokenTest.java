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
