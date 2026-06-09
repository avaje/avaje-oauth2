module io.avaje.oauth2.core {

    exports io.avaje.oauth2.core.data;
    exports io.avaje.oauth2.core.jwt;
    exports io.avaje.oauth2.core.pkce;

    requires transitive io.avaje.json;
    requires transitive java.net.http;
}
