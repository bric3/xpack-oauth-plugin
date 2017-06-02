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
package fr.arkey.elasticsearch.oauth.realm.tokeninfo;

import java.util.Optional;

/**
 * Contract that says I will return token info for an access token
 */
public interface OAuthTokenRetriever {

    /**
     * Retrieve token info is possible.
     *
     * @param accessToken the access token
     * @return Optional containing the token info for the given access token, or empty optional
     */
    Optional<TokenInfo> getTokenInfo(String accessToken);
}
