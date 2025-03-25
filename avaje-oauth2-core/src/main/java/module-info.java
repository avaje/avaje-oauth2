module io.avaje.oauth2.core {

    exports io.avaje.oauth2.core.data;
    exports io.avaje.oauth2.core.jwt;

    requires transitive io.avaje.json;
    requires transitive io.avaje.http.client;
}