package fr.arkey.elasticsearch.oauth.tools;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.util.StdConverter;

import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.joining;
import static com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES;
import static com.google.common.collect.Sets.newHashSet;

public final class OAuthTokenPayload {

    @JsonProperty("access_token")
    public final String accessToken;

    @JsonProperty("token_type")
    public final String tokenType;

    @JsonProperty("refresh_token")
    public final String refreshToken;

    @JsonProperty("expires_in")
    private final Integer expiresIn;

    @JsonIgnore
    public final LocalDateTime expiresAt;

    @JsonProperty("issued_at")
    public final Long issuedAt;

    @JsonProperty("client_id")
    public final String clientId;

    @JsonProperty("user_id")
    public final String userId;

    @JsonProperty("scope")
    @JsonSerialize(converter = OAuthScopes.OAuthScopesConverter.class)
    public final OAuthScopes scope;

    @JsonCreator
    public OAuthTokenPayload(@JsonProperty("access_token") String accessToken,
                             @JsonProperty("refresh_token") String refreshToken,
                             @JsonProperty("token_type") String tokenType,
                             @JsonProperty("expires_in") Integer expiresIn,
                             @JsonProperty("issued_at") Long issuedAt,
                             @JsonProperty("client_id") String clientId,
                             @JsonProperty("user_id") String userId,
                             @JsonProperty("scope") Set<String> scopes) {

        this(accessToken,
             tokenType,
             refreshToken,
             expiresIn,
             issuedAt,
             clientId,
             userId,
             OAuthScopes.scopes(scopes));
    }

    public OAuthTokenPayload(String accessToken,
                             String refreshToken,
                             String tokenType,
                             Integer expiresIn,
                             Long issuedAt,
                             String clientId,
                             String userId,
                             OAuthScopes scope) {

        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.expiresAt = LocalDateTime.now().withNano(0).plusSeconds(expiresIn); // oauth has a precision up to the second
        this.issuedAt = issuedAt;
        this.clientId = clientId;
        this.userId = userId;
        this.scope = scope;
    }

    @JsonIgnore
    public final boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OAuthTokenPayload that = (OAuthTokenPayload) o;
        return Objects.equals(accessToken, that.accessToken) &&
               Objects.equals(tokenType, that.tokenType) &&
               Objects.equals(refreshToken, that.refreshToken) &&
               Objects.equals(expiresIn, that.expiresIn) &&
               Objects.equals(expiresAt, that.expiresAt) &&
               Objects.equals(issuedAt, that.issuedAt) &&
               Objects.equals(clientId, that.clientId) &&
               Objects.equals(userId, that.userId) &&
               Objects.equals(scope, that.scope);
    }

    @Override
    public int hashCode() {
        return Objects.hash(accessToken, tokenType, refreshToken, expiresIn, expiresAt, issuedAt, clientId, userId, scope);
    }

    @Override
    public String toString() {
        return "OAuthTokenPayload{" +
               "accessToken='" + accessToken + '\'' +
               ", tokenType='" + tokenType + '\'' +
               ", refreshToken='" + refreshToken + '\'' +
               ", expiresIn=" + expiresIn +
               ", expiresAt=" + expiresAt +
               ", issuedAt=" + issuedAt +
               ", clientId='" + clientId + '\'' +
               ", userId='" + userId + '\'' +
               ", scope=" + scope +
               '}';
    }

    public static final class OAuthScopes {

        private final Set<String> value;

        public static OAuthScopes scopes(String scopeString, char separator) {
            return new OAuthScopes(Pattern.compile(Character.toString(separator))
                                          .splitAsStream(scopeString)
                                          .map(String::trim)
                                          .collect(Collectors.toSet()));
        }

        public static OAuthScopes scopes(String... values) {
            return new OAuthScopes(newHashSet(values));
        }

        public static OAuthScopes scopes(Set<String> scopes) {
            return new OAuthScopes(scopes == null ? new HashSet<>() : new HashSet<>(scopes));
        }

        private OAuthScopes(Set<String> scopes) {
            this.value = scopes;
        }

        public String joinOn(String separator) {
            return value.stream().collect(joining(separator));
        }

        public Set<String> toSet() {
            return unmodifiableSet(value);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            OAuthScopes that = (OAuthScopes) o;
            return Objects.equals(value, that.value);
        }

        @Override
        public int hashCode() {
            return Objects.hash(value);
        }

        @Override
        public String toString() {
            return "OAuthScopes{" +
                   "value=" + value +
                   '}';
        }

        private static class OAuthScopesConverter extends StdConverter<OAuthScopes, Set<String>> {
            @Override
            public Set<String> convert(OAuthScopes value) {
                return value.toSet();
            }
        }
    }

    public static class JsonMapper {

        private static final ObjectMapper mapper = new ObjectMapper().disable(FAIL_ON_UNKNOWN_PROPERTIES);

        public static OAuthTokenPayload fromJson(String serializedToken) {
            try {
                return mapper.readValue(serializedToken, OAuthTokenPayload.class);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        public static String toJson(OAuthTokenPayload oAuthTokenPayload) {
            try {
                return mapper.writeValueAsString(oAuthTokenPayload);
            } catch (JsonProcessingException e) {
                throw new UncheckedIOException(e);
            }
        }

    }
}
