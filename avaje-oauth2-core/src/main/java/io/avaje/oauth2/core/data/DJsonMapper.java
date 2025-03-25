package io.avaje.oauth2.core.data;

import io.avaje.json.JsonAdapter;
import io.avaje.json.JsonReader;
import io.avaje.json.JsonWriter;
import io.avaje.json.PropertyNames;
import io.avaje.json.mapper.JsonExtract;
import io.avaje.json.mapper.JsonMapper;
import io.avaje.json.mapper.JsonMapper.Type;

import java.io.InputStream;
import java.util.List;

/**
 * Maps JSON input to KeySet.
 */
final class DJsonMapper implements JsonDataMapper {

    private final Type<KeySet> keySetType;
    private final Type<JwtHeader> jwtHeader;
    private final Type<OidcTokens> oidcType;
    private final Type<IdClaims> idClaimsType;
    private final Type<AccessToken> accessTokenType;

    private DJsonMapper(Type<KeySet> keySetType,
                        Type<JwtHeader> jwtHeader,
                        Type<OidcTokens> oidcType,
                        Type<IdClaims> idClaimsType,
                        Type<AccessToken> accessTokenType) {
        this.keySetType = keySetType;
        this.jwtHeader = jwtHeader;
        this.oidcType = oidcType;
        this.idClaimsType = idClaimsType;
        this.accessTokenType = accessTokenType;
    }

    static Builder builder() {
        return new DBuilder();
    }

    @Override
    public IdClaims readIdClaims(String json) {
        return idClaimsType.fromJson(json);
    }

    @Override
    public OidcTokens readOidcTokens(String json) {
        return oidcType.fromJson(json);
    }

    @Override
    public KeySet readKeySet(String json) {
        return keySetType.fromJson(json);
    }

    @Override
    public KeySet readKeySet(InputStream is) {
        return keySetType.fromJson(is);
    }

    @Override
    public JwtHeader readJwtHeader(String jwtHeaderJson) {
        return jwtHeader.fromJson(jwtHeaderJson);
    }

    @Override
    public AccessToken readAccessToken(String json) {
        return accessTokenType.fromJson(json);
    }

    private static final class DBuilder implements JsonDataMapper.Builder {

        private JsonMapper mapper;

        @Override
        public Builder jsonMapper(JsonMapper simpleMapper) {
            this.mapper = simpleMapper;
            return this;
        }

        @Override
        public JsonDataMapper build() {
            if (mapper == null) {
                mapper = JsonMapper.builder().build();
            }
            Type<KeySet.KeyInfo> keyInfo = mapper.type(new KeyInfoJsonAdapter(mapper));
            Type<KeySet> keySet = mapper.type(new KeySetJsonAdapter(keyInfo.list()));
            Type<JwtHeader> jwtHeader = mapper.type(new HeaderAdapter(mapper));
            Type<OidcTokens> oidc = mapper.type(new OIDCTokensJsonAdapter(mapper));
            Type<IdClaims> idClaimsType = mapper.type(new IdClaimsAdapter(mapper));
            Type<AccessToken> accessTokenType = mapper.type(AccessTokenAdapter::new);

            return new DJsonMapper(keySet, jwtHeader, oidc, idClaimsType, accessTokenType);
        }
    }

    private static final class HeaderAdapter implements JsonAdapter<JwtHeader> {

        private final JsonMapper simpleMapper;

        private HeaderAdapter(JsonMapper simpleMapper) {
            this.simpleMapper = simpleMapper;
        }

        @Override
        public void toJson(JsonWriter jsonWriter, JwtHeader jwtHeader) {
            throw new UnsupportedOperationException();
        }

        @Override
        public JwtHeader fromJson(JsonReader jsonReader) {
            JsonExtract header = JsonExtract.of(simpleMapper.fromJsonObject(jsonReader));
            String kid = header.extract("kid", "");
            String alg = header.extract("alg", "");
            return new JwtHeader(kid, alg);
        }
    }

    private static final class KeyInfoJsonAdapter implements JsonAdapter<KeySet.KeyInfo> {

        private final PropertyNames names;

        KeyInfoJsonAdapter(JsonMapper mapper) {
            this.names = mapper.properties("alg", "e", "kid", "kty", "n", "use");
        }

        @Override
        public void toJson(JsonWriter writer, KeySet.KeyInfo keyInfo) {
            throw new UnsupportedOperationException();
        }

        @Override
        public KeySet.KeyInfo fromJson(JsonReader reader) {
            String     _val$algorithm = null;
            String     _val$exponent = null;
            String     _val$kid = null;
            String     _val$kty = null;
            String     _val$modulus = null;
            String     _val$use = null;

            reader.beginObject(names);
            while (reader.hasNextField()) {
                final String fieldName = reader.nextField();
                switch (fieldName) {
                    case "alg":
                        _val$algorithm = reader.readString();
                        break;
                    case "e":
                        _val$exponent = reader.readString();
                        break;
                    case "kid":
                        _val$kid = reader.readString();
                        break;
                    case "kty":
                        _val$kty = reader.readString();
                        break;
                    case "n":
                        _val$modulus = reader.readString();
                        break;
                    case "use":
                        _val$use = reader.readString();
                        break;
                    default:
                        reader.unmappedField(fieldName);
                        reader.skipValue();
                }
            }
            reader.endObject();
            return new KeySet.KeyInfo(_val$algorithm, _val$exponent, _val$kid, _val$kty, _val$modulus, _val$use);
        }
    }

    private static final class KeySetJsonAdapter implements JsonAdapter<KeySet> {

        private final Type<List<KeySet.KeyInfo>> listReader;

        KeySetJsonAdapter(Type<List<KeySet.KeyInfo>> listReader) {
            this.listReader = listReader;
        }

        @Override
        public void toJson(JsonWriter writer, KeySet keySet) {
            throw new UnsupportedOperationException();
        }

        @Override
        public KeySet fromJson(JsonReader reader) {
            List<KeySet.KeyInfo> _val$keys = null;

            // read json
            reader.beginObject();
            while (reader.hasNextField()) {
                final String fieldName = reader.nextField();
                if (fieldName.equals("keys")) {
                    _val$keys = listReader.fromJson(reader);
                } else {
                    reader.unmappedField(fieldName);
                    reader.skipValue();
                }
            }
            reader.endObject();
            return new KeySet(_val$keys);
        }
    }

    private static final class OIDCTokensJsonAdapter implements JsonAdapter<OidcTokens> {

        private final PropertyNames names;

        OIDCTokensJsonAdapter(JsonMapper mapper) {
            this.names = mapper.properties("id_token", "access_token", "refresh_token", "expires_in", "token_type");
        }

        @Override
        public void toJson(JsonWriter writer, OidcTokens oidctokens) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OidcTokens fromJson(JsonReader reader) {
            String     _val$idToken = null;
            String     _val$accessToken = null;
            String     _val$refreshToken = null;
            long       _val$expiresIn = 0;
            String     _val$tokenType = null;

            reader.beginObject(names);
            while (reader.hasNextField()) {
                final String fieldName = reader.nextField();
                switch (fieldName) {
                    case "id_token":
                        _val$idToken = reader.readString();
                        break;

                    case "access_token":
                        _val$accessToken = reader.readString();
                        break;

                    case "refresh_token":
                        _val$refreshToken = reader.readString();
                        break;

                    case "expires_in":
                        _val$expiresIn = reader.readLong();
                        break;

                    case "token_type":
                        _val$tokenType = reader.readString();
                        break;

                    default:
                        reader.unmappedField(fieldName);
                        reader.skipValue();
                }
            }
            reader.endObject();

            return new OidcTokens(_val$idToken, _val$accessToken, _val$refreshToken, _val$expiresIn, _val$tokenType);
        }
    }

    static final class IdClaimsAdapter implements JsonAdapter<IdClaims> {

        private final JsonMapper mapper;
        private final PropertyNames names;

        IdClaimsAdapter(JsonMapper mapper) {
            this.mapper = mapper;
            this.names = mapper.properties("sub", "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "email", "email_verified", "gender", "birthdate", "zoneinfo", "locale", "phone_number", "phone_number_verified", "updated_at");
        }

        @Override
        public void toJson(JsonWriter writer, IdClaims idClaims) {
            throw new UnsupportedOperationException();
        }

        @Override
        public IdClaims fromJson(JsonReader reader) {
            // variables to read json values into, constructor params don't need _set$ flags
            String     _val$sub = null;
            String     _val$name = null;
            String     _val$givenName = null;
            String     _val$familyName = null;
            String     _val$middleName = null;
            String     _val$nickname = null;
            String     _val$preferredUsername = null;
            String     _val$profile = null;
            String     _val$picture = null;
            String     _val$website = null;
            String     _val$email = null;
            boolean    _val$emailVerified = false;
            String     _val$gender = null;
            String     _val$birthdate = null;
            String     _val$zoneinfo = null;
            String     _val$locale = null;
            String     _val$phoneNumber = null;
            boolean    _val$phoneNumberVerified = false;
            long       _val$updatedAt = 0;
            Object     _val$custom = null;
            var unmapped = new java.util.LinkedHashMap<String, Object>();

            // read json
            reader.beginObject(names);
            while (reader.hasNextField()) {
                final String fieldName = reader.nextField();
                switch (fieldName) {
                    case "sub":
                        _val$sub = reader.readString();
                        break;

                    case "name":
                        _val$name = reader.readString();
                        break;

                    case "givenName":
                        _val$givenName = reader.readString();
                        break;

                    case "familyName":
                        _val$familyName = reader.readString();
                        break;

                    case "middleName":
                        _val$middleName = reader.readString();
                        break;

                    case "nickname":
                        _val$nickname = reader.readString();
                        break;

                    case "preferredUsername":
                        _val$preferredUsername = reader.readString();
                        break;

                    case "profile":
                        _val$profile = reader.readString();
                        break;

                    case "picture":
                        _val$picture = reader.readString();
                        break;

                    case "website":
                        _val$website = reader.readString();
                        break;

                    case "email":
                        _val$email = reader.readString();
                        break;

                    case "emailVerified":
                        _val$emailVerified = reader.readBoolean();
                        break;

                    case "gender":
                        _val$gender = reader.readString();
                        break;

                    case "birthdate":
                        _val$birthdate = reader.readString();
                        break;

                    case "zoneinfo":
                        _val$zoneinfo = reader.readString();
                        break;

                    case "locale":
                        _val$locale = reader.readString();
                        break;

                    case "phoneNumber":
                        _val$phoneNumber = reader.readString();
                        break;

                    case "phoneNumberVerified":
                        _val$phoneNumberVerified = reader.readBoolean();
                        break;

                    case "updatedAt":
                        _val$updatedAt = reader.readLong();
                        break;

                    default:
                        var value = mapper.fromJson(reader);
                        unmapped.put(fieldName, value);
                }
            }
            reader.endObject();

            // build and return IdClaims
            return new IdClaims(_val$sub, _val$name, _val$givenName, _val$familyName, _val$middleName, _val$nickname, _val$preferredUsername, _val$profile, _val$picture, _val$website, _val$email, _val$emailVerified, _val$gender, _val$birthdate, _val$zoneinfo, _val$locale, _val$phoneNumber, _val$phoneNumberVerified, _val$updatedAt, unmapped);
        }
    }

    static final class AccessTokenAdapter implements JsonAdapter<AccessToken> {

        private final PropertyNames names;

        AccessTokenAdapter(JsonMapper mapper) {
            this.names = mapper.properties("sub", "token_use", "scope", "auth_time", "iss", "exp", "iat", "version", "jti", "client_id");
        }

        @Override
        public void toJson(JsonWriter writer, AccessToken accessToken) {
            throw new UnsupportedOperationException();
        }

        @Override
        public AccessToken fromJson(JsonReader reader) {
            // variables to read json values into, constructor params don't need _set$ flags
            String     _val$sub = null;
            String     _val$tokenUse = null;
            String     _val$scope = null;
            long       _val$authTime = 0;
            String       _val$issuer = null;
            long       _val$expiredAt = 0;
            long       _val$issuedAt = 0;
            int        _val$version = 0;
            String     _val$jti = null;
            String     _val$clientId = null;

            // read json
            reader.beginObject(names);
            while (reader.hasNextField()) {
                final String fieldName = reader.nextField();
                switch (fieldName) {
                    case "sub":
                        _val$sub = reader.readString();
                        break;

                    case "token_use":
                        _val$tokenUse = reader.readString();
                        break;

                    case "scope":
                        _val$scope = reader.readString();
                        break;

                    case "auth_time":
                        _val$authTime = reader.readLong();
                        break;

                    case "iss":
                        _val$issuer = reader.readString();
                        break;

                    case "exp":
                        _val$expiredAt = reader.readLong();
                        break;

                    case "iat":
                        _val$issuedAt = reader.readLong();
                        break;

                    case "version":
                        _val$version = reader.readInt();
                        break;

                    case "jti":
                        _val$jti = reader.readString();
                        break;

                    case "client_id":
                        _val$clientId = reader.readString();
                        break;

                    default:
                        reader.unmappedField(fieldName);
                        reader.skipValue();
                }
            }
            reader.endObject();
            return new AccessToken(_val$sub, _val$tokenUse, _val$scope, _val$authTime, _val$issuer, _val$expiredAt, _val$issuedAt, _val$version, _val$jti, _val$clientId);
        }
    }
}
