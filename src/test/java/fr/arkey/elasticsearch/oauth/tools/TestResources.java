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
package fr.arkey.elasticsearch.oauth.tools;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.Properties;

public class TestResources {

    private static final Properties TEST_PROPERTIES = tryResource("test.properties")
            .map(TestResources::loadFromFile)
            .orElseGet(() -> {
                System.err.println("couldn't load property file, loading empty");
                return new Properties();
            });

    public static int idpPort() {
        return Integer.parseInt(TEST_PROPERTIES.getProperty("idp.port"));
    }

    public static Optional<Path> tryResource(String resource) {
        return Optional.ofNullable(TestResources.class.getClassLoader().getResource(resource))
                       .map(URL::getFile)
                       .map(Paths::get);
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
