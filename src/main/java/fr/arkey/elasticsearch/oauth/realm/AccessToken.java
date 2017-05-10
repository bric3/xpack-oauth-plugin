package fr.arkey.elasticsearch.oauth.realm;

import java.util.Objects;
import fr.arkey.elasticsearch.oauth.realm.support.OAuthRealmExceptions;
import org.elasticsearch.shield.authc.AuthenticationToken;

public class AccessToken implements AuthenticationToken {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_AUTH_PREFIX = "Bearer ";
    public final String tokenString;

    public AccessToken(String header) {
        tokenString = checkHeader(header).substring(BEARER_AUTH_PREFIX.length()).trim();
    }

    private String checkHeader(String header) {
        if (header.length() <= BEARER_AUTH_PREFIX.length() || !isBearer(header)) {
            throw OAuthRealmExceptions.authorizationException();
        }
        return header;
    }

    @Override
    public String principal() {
        // known usage are for log :
        // org.elasticsearch.shield.authc.DefaultAuthenticationFailureHandler.unsuccessfulAuthentication(org.elasticsearch.rest.RestRequest, org.elasticsearch.shield.authc.AuthenticationToken)
        // org.elasticsearch.shield.audit.logfile.LoggingAuditTrail.authenticationFailed(org.elasticsearch.shield.authc.AuthenticationToken, org.elasticsearch.rest.RestRequest)
        return BEARER_AUTH_PREFIX + tokenString;
    }

    @Override
    public Object credentials() {
        return tokenString;
    }

    @Override
    public void clearCredentials() {
        // not supported
    }

    public static boolean isBearer(String header) {
        return header.startsWith(BEARER_AUTH_PREFIX);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AccessToken that = (AccessToken) o;
        return Objects.equals(tokenString, that.tokenString);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tokenString);
    }
}
