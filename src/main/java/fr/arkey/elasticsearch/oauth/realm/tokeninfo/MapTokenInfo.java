package fr.arkey.elasticsearch.oauth.realm.tokeninfo;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import com.google.common.collect.ImmutableSet;
import fr.arkey.elasticsearch.oauth.realm.support.OAuthRealmExceptions;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.shield.authc.RealmConfig;

import static java.time.temporal.ChronoUnit.SECONDS;
import static java.util.stream.Collectors.joining;

public class MapTokenInfo implements Function<Map<String, Object>, TokenInfo> {
    private final ESLogger logger;
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
    public TokenInfo apply(Map<String, Object> jsonMap) {
        return new TokenInfo(
                extractFromMap(jsonMap, userIdField, String.class),
                extractFromMap(jsonMap, expiresInField, Integer.class),
                expiresInUnit,
                // XXX can I trust the payload
                ImmutableSet.copyOf(extractFromMap(jsonMap, scopeField, List.class))
        );
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
