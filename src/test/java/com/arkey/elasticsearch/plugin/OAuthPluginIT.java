package com.arkey.elasticsearch.plugin;

import org.junit.Rule;
import org.junit.Test;

public class OAuthPluginIT {

    @Rule
    public ESClient esClient = new ESClient("http://localhost:9400/",
                                            "admin_user",
                                            "changeme");

    
    @Test
    public void make_sure_plugin_is_loaded() {
        // Given

        // When


        // Then

    }
}

