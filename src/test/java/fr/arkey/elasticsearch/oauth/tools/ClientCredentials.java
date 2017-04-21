package fr.arkey.elasticsearch.oauth.tools;

public class ClientCredentials {
    public final String client_id;
    public final String client_secret;

    private ClientCredentials(String client_id, String client_secret) {
        this.client_id = client_id;
        this.client_secret = client_secret;
    }

    public static ClientCredentials clientCredentials(String client_id, String client_secret) {
        return new ClientCredentials(client_id, client_secret);
    }
}
