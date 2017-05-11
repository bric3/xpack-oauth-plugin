package fr.arkey.elasticsearch.oauth.tools;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

public class TestResources {

    private static final Properties TEST_PROPERTIES = loadFromFile(testResourcesPath().resolve("test.properties"));

    public static int idpPort() {
        return Integer.parseInt(TEST_PROPERTIES.getProperty("idp.port"));
    }

    public static Path testResourcesPath() {
        return Paths.get(TestResources.class.getClassLoader().getResource("").getPath());
    }

    private static Properties loadFromFile(Path configLocation) {
        System.out.println("Config location: " + configLocation.toString());
        try (InputStream stream = Files.newInputStream(configLocation)) {
            Properties config = new Properties();
            config.load(stream);
            return config;
        } catch (IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }
}
