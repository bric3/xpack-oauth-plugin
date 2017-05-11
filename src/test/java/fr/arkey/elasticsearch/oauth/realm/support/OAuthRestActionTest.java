package fr.arkey.elasticsearch.oauth.realm.support;

import org.elasticsearch.client.Client;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.test.rest.FakeRestRequest;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class OAuthRestActionTest {
    @Test
    public void should_register_controller() {
        RestController restController = mock(RestController.class);
        OAuthRestAction oAuthRestAction = new OAuthRestAction(Settings.builder().build(), mock(Client.class), restController);

        verify(restController).registerHandler(eq(RestRequest.Method.GET),
                                               eq("/_oauth/state"),
                                               same(oAuthRestAction));
    }

    @Test
    public void should_juste_return_json_payload_with_active_status_set_to_true() throws Exception {
        // Given
        OAuthRestAction oAuthRestAction = new OAuthRestAction(Settings.builder().build(), mock(Client.class), mock(RestController.class));

        // When
        RestChannel channel = mock(RestChannel.class);
        oAuthRestAction.handleRequest(new FakeRestRequest(), channel, mock(Client.class));

        // Then
        ArgumentCaptor<RestResponse> restResponse = ArgumentCaptor.forClass(RestResponse.class);
        verify(channel).sendResponse(restResponse.capture());

        assertThat(restResponse.getValue().contentType()).isEqualTo("application/json; charset=UTF-8");
        assertThat(restResponse.getValue().content().toUtf8()).isEqualTo("{\"active\":true}");
    }
}
