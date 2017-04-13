package com.arkey.elasticsearch.plugin;

import java.util.Collection;
import java.util.Collections;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.shield.ShieldPlugin;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.rest.client.http.HttpResponse;
import org.junit.Test;

import static org.hamcrest.Matchers.is;


/* Run before : mvn -Dskip.integ.tests=false pre-integration-test
 * Stop ES :
 */
public class OAuthRealmPluginIT extends ESIntegTestCase {


    

    @Override
    protected Collection<Class<? extends Plugin>> transportClientPlugins() {
        return Collections.<Class<? extends Plugin>>singleton(ShieldPlugin.class);
    }

    @Test
    public void testHttpConnectionWithNoAuthentication() throws Exception {
        HttpResponse response = httpClient().path("/").execute();
        assertThat(response.getStatusCode(), is(401));
        String value = response.getHeaders().get("WWW-Authenticate");
        assertThat(value, is("custom-challenge"));
    }

}
