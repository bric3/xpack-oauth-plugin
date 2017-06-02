/*
 * Copyright 2017 Brice Dutheil
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fr.arkey.elasticsearch.oauth.realm;

import fr.arkey.elasticsearch.oauth.realm.support.OAuthRealmExceptions;
import org.elasticsearch.xpack.security.authc.AuthenticationToken;

import java.util.Objects;

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
