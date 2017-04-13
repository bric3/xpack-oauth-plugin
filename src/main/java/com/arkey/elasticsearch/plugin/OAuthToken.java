package com.arkey.elasticsearch.plugin;

import org.elasticsearch.shield.authc.AuthenticationToken;

public class OAuthToken implements AuthenticationToken {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BASIC_AUTH_PREFIX = "Bearer ";
    private final String tokenString;

    public OAuthToken(String header) {
        tokenString = header.substring(BASIC_AUTH_PREFIX.length());
    }


    @Override
    public String principal() {
        return null;
    }

    @Override
    public Object credentials() {
        return null;
    }

    @Override
    public void clearCredentials() {
        // not supported
    }

    public static boolean isBearer(String header) {
        return header.startsWith(BASIC_AUTH_PREFIX);
    }
}
