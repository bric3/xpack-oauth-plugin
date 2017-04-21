package fr.arkey.elasticsearch.oauth.tools;

import java.io.IOException;
import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.Assume;
import org.junit.rules.MethodRule;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;

public class ESClient implements MethodRule {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BASIC_PREFIX = "Basic ";
    private final String password;
    private final String user;
    private final String esURL;

    private OkHttpClient basicClient = HttpClients.simpleHttpClient();
    private boolean checkRunning = true;

    public ESClient(String esURL, String user, String password) {
        this.esURL = esURL;
        this.user = user;
        this.password = password;
    }

    @Override
    public Statement apply(final Statement base, FrameworkMethod method, Object target) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                Assume.assumeTrue("Couldn't reach Elasticsearch", !checkRunning || isRunning());
                base.evaluate();
            }
        };
    }

    public boolean isRunning() throws IOException {
        Request request = new Request.Builder()
                .url(esURL)
                .addHeader(AUTHORIZATION_HEADER,
                           Credentials.basic(user, password))
                .build();

        Response response = basicClient.newCall(request).execute();

        if (!response.isSuccessful()) {
            System.err.println(request.headers());
            System.err.println(response.headers());
            System.err.println(response.body().string());
        }

        return response.isSuccessful();
    }

    public ESClient checkRunning(boolean checkRunning) {
        this.checkRunning = checkRunning;
        return this;
    }
}
