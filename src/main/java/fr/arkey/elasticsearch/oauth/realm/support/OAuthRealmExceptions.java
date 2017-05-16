package fr.arkey.elasticsearch.oauth.realm.support;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.rest.RestStatus;

public class OAuthRealmExceptions {
    public static ElasticsearchSecurityException authorizationException() {
        ElasticsearchSecurityException e = new ElasticsearchSecurityException(
                "Authentication failed",
                RestStatus.UNAUTHORIZED);
        e.addHeader("WWW-Authenticate", "Bearer realm=\"shield\" charset=\"UTF-8\"");
        return e;
    }

    public static ElasticsearchSecurityException authorizationException(Throwable cause) {
        ElasticsearchSecurityException e = new ElasticsearchSecurityException(
                "Authentication failed",
                RestStatus.UNAUTHORIZED,
                cause);
        e.addHeader("WWW-Authenticate", "Bearer realm=\"shield\" charset=\"UTF-8\"");
        return e;
    }

    public static ElasticsearchSecurityException authorizationException(String wwwAuthenticateError) {
        ElasticsearchSecurityException e = new ElasticsearchSecurityException(
                "Authentication failed",
                RestStatus.UNAUTHORIZED
                );
        e.addHeader("WWW-Authenticate", "Bearer realm=\"shield\" charset=\"UTF-8\" delegateError=\"" + wwwAuthenticateError + "\"");
        return e;
    }
}
