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

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.Set;

import static java.time.LocalDateTime.now;

public class TokenInfo {
    public String userId;
    public LocalDateTime expiresAt;
    private ZoneId zone;
    public Set<String> scopes;

    public TokenInfo(String userId, Integer expiresIn, ChronoUnit expiresInUnit, Set<String> scopes) {
        this(userId,
             expiresIn,
             expiresInUnit,
             ZoneId.systemDefault(),
             scopes);
    }

    public TokenInfo(String userId, Integer expiresIn, ChronoUnit expiresInUnit, ZoneId zone, Set<String> scopes) {
        this(userId,
             LocalDateTime.now(zone).withNano(0).plus(expiresIn, expiresInUnit),
             zone,
             scopes);
    }

    public TokenInfo(String userId, LocalDateTime expiresAt, ZoneId zone, Set<String> scopes) {
        this.userId = userId;
        this.expiresAt = expiresAt;
        this.zone = zone;
        this.scopes = scopes;
    }

    public final boolean isExpired() {
        return now(zone).isAfter(expiresAt);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TokenInfo tokenInfo = (TokenInfo) o;
        return Objects.equals(userId, tokenInfo.userId) &&
               Objects.equals(expiresAt, tokenInfo.expiresAt) &&
               Objects.equals(zone, tokenInfo.zone) &&
               Objects.equals(scopes, tokenInfo.scopes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, expiresAt, zone, scopes);
    }
}
