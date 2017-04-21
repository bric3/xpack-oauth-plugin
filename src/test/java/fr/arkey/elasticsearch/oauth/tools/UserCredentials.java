package fr.arkey.elasticsearch.oauth.tools;

public class UserCredentials {
    public final String username;
    public final String password;

    private UserCredentials(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public static UserCredentials userCredentials(String username, String password) {
        return new UserCredentials(username, password);
    }
}
