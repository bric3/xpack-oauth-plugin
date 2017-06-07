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

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.xpack.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.security.authc.DefaultAuthenticationFailureHandler;

/**
 * Failure handler that detects when an authentication fails due to a unknown access token.
 *
 * Other failures are ignored because this implementation doesn't know which authentication has been used.
 * As {@link ElasticsearchSecurityException} header is a map, we cannot have multiple {@code WWW-Authenticate}
 * header lines, the only option is to add the auth scheme on the same line. Also it seems that it checks this header
 * only contains one value. Indeed this header grammar is ambiguous see this this answer on
 * <a href="http://stackoverflow.com/questions/10239970/what-is-the-delimiter-for-www-authenticate-for-multiple-schemes">StackOverflow</a>.
 *
 * So the only thing handled is {@link #failedAuthentication(RestRequest, AuthenticationToken, ThreadContext)}, others are ignored.
 */
public class OAuthAuthenticationFailureHandler extends DefaultAuthenticationFailureHandler {

    @Override
    public ElasticsearchSecurityException failedAuthentication(RestRequest request, AuthenticationToken token, ThreadContext context) {
        ElasticsearchSecurityException e = super.failedAuthentication(request, token, context);
        if (token instanceof AccessToken) {
            e.addHeader("WWW-Authenticate", "Bearer realm=\"security\" charset=\"UTF-8\"");
        }
        return e;
    }
}
