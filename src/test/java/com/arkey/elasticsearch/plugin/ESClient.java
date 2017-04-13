package com.arkey.elasticsearch.plugin;

import java.io.IOException;
import java.util.Base64;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.Assume;
import org.junit.rules.MethodRule;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;

import static java.lang.String.format;

public class ESClient implements MethodRule {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BASIC_PREFIX = "Basic ";
    private final String password;
    private final String user;
    private String url;
    private OkHttpClient client = new OkHttpClient.Builder().build();

    public ESClient(String url, String user, String password) {
        this.url = url;
        this.user = user;
        this.password = password;
    }

    @Override
    public Statement apply(final Statement base, FrameworkMethod method, Object target) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                Assume.assumeTrue("Couldn't reach Elasticsearch", is_running());
                base.evaluate();
            }
        };
    }

    public boolean is_running() throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .addHeader(AUTHORIZATION_HEADER,
                           BASIC_PREFIX + Base64.getEncoder().encodeToString((format("%s:%s", user, password)).getBytes("UTF-8")))
                .build();

        Response response = client.newCall(request).execute();

        if (!response.isSuccessful()) {
            System.err.println(request.headers());
            System.err.println(response.headers());
            System.err.println(response.body().string());
        }

        return response.isSuccessful();
    }
}
