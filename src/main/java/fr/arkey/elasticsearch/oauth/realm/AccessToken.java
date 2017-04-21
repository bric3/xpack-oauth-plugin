package fr.arkey.elasticsearch.oauth.realm;

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
        return null;
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
}
