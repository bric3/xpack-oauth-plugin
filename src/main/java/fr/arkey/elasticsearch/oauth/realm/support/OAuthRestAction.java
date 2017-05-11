package fr.arkey.elasticsearch.oauth.realm.support;

import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

public class OAuthRestAction extends BaseRestHandler {
    @Inject
    public OAuthRestAction(Settings settings,
                           Client client,
                           RestController controller) {
        super(settings, controller, client);
        controller.registerHandler(RestRequest.Method.GET, "/_oauth/state", this);
    }

    @Override
    protected void handleRequest(RestRequest request,
                                 RestChannel channel,
                                 Client client) throws Exception {
        channel.sendResponse(new BytesRestResponse(RestStatus.OK,
                                                   JsonXContent.contentBuilder()
                                                               .startObject()
                                                               .field("active", true)
                                                               .endObject()));
    }
}
