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

import com.google.common.collect.ImmutableSet;
import fr.arkey.elasticsearch.oauth.realm.support.OAuthRealmExceptions;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.xpack.security.authc.RealmConfig;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

import static java.time.temporal.ChronoUnit.SECONDS;
import static java.util.stream.Collectors.joining;
import static org.elasticsearch.common.xcontent.json.JsonXContent.jsonXContent;

public class MapTokenInfo implements Function<InputStream, TokenInfo> {
    private final Logger logger;
    private final String userIdField;
    private final String expiresInField;
    private final ChronoUnit expiresInUnit;
    private final String scopeField;

    public MapTokenInfo(RealmConfig config) {
        logger = config.logger(this.getClass());
        userIdField = Objects.requireNonNull(config.settings().get("token-info.field.user"), "missing required setting [token-info.field.user]");
        expiresInField = Objects.requireNonNull(config.settings().get("token-info.field.expires-in"), "missing required setting [token-info.field.expires-in]");
        expiresInUnit = ChronoUnit.valueOf(config.settings()
                                                 .get("token-info.field.expires-in.unit", SECONDS.name())
                                                 .toUpperCase(Locale.getDefault()));
        scopeField = Objects.requireNonNull(config.settings().get("token-info.field.scope"), "missing required setting [token-info.field.scope]");
    }

    @SuppressWarnings("unchecked")
    @Override
    public TokenInfo apply(InputStream inputStream) {
        try {
            Map<String, Object> jsonMap = jsonXContent.createParser(NamedXContentRegistry.EMPTY, inputStream).map();
            logger.debug("User authenticated via access token, token info : {}", jsonMap);

            return new TokenInfo(
                    extractFromMap(jsonMap, userIdField, String.class),
                    extractFromMap(jsonMap, expiresInField, Integer.class),
                    expiresInUnit,
                    // XXX can I trust the payload
                    ImmutableSet.copyOf(extractFromMap(jsonMap, scopeField, List.class))
            );
        } catch (IOException ioe) {
            logger.error("Could not authenticate user, could be a connection issue", ioe);
            throw new UncheckedIOException(ioe);
        }
    }

    private <T> T extractFromMap(Map<String, Object> jsonMap, String field, Class<T> type) {
        Object value = jsonMap.get(field);
        if (type.isInstance(value)) {
            return type.cast(value);
        }
        logger.warn("Cannot extract '{}' token info having the following fields '{}', is oauth realm properly configured ?",
                    field,
                    jsonMap.keySet().stream().collect(joining(", ", "[", "]")));
        throw OAuthRealmExceptions.authorizationException();
    }
}
