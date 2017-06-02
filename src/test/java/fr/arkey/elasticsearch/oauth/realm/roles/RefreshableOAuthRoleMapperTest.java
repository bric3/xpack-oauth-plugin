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
package fr.arkey.elasticsearch.oauth.realm.roles;

import java.io.IOException;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Set;
import fr.arkey.elasticsearch.oauth.realm.OAuthRealm;
import fr.arkey.elasticsearch.oauth.tools.TestResources;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.watcher.ResourceWatcher;
import org.elasticsearch.watcher.ResourceWatcherService;
import org.elasticsearch.watcher.ResourceWatcherService.Frequency;
import org.elasticsearch.xpack.security.authc.RealmConfig;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import static java.nio.file.StandardCopyOption.COPY_ATTRIBUTES;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

public class RefreshableOAuthRoleMapperTest {
    @Rule
    public TemporaryFolder home = new TemporaryFolder();
    @Rule
    public MockitoRule rule = MockitoJUnit.rule();

    private RefreshableOAuthRoleMapper mapper;

    @Mock
    private ResourceWatcherService resourceWatcherService;
    @Mock
    private Runnable onResourceRefresh;


    @Test
    public void load_role_user_mapping_upon_creation() {
        assertThat(mapper.rolesFor("123", scopes())).contains("user");
        assertThat(mapper.rolesFor("321", scopes())).contains("user", "admin");
        assertThat(mapper.rolesFor("no_defined", scopes())).isEmpty();
    }

    @Test
    public void can_reload_role_user_mapping() throws IOException {
        // initialize watcher
        ArgumentCaptor<ResourceWatcher> resourceWatcher = ArgumentCaptor.forClass(ResourceWatcher.class);
        verify(resourceWatcherService).add(resourceWatcher.capture(), any(Frequency.class));
        resourceWatcher.getValue().checkAndNotify();

        assertThat(mapper.rolesFor("321", scopes())).contains("user", "admin");


        // change file
        Files.write(home.getRoot().toPath().resolve("oauth_role_mapping.yml"),
                    ("only-role:\n" +
                     "  - user1\n" +
                     "  - \"user2\"").getBytes("UTF-8"),
                    TRUNCATE_EXISTING);

        // manually tell resourceWatcher that file changed
        resourceWatcher.getValue().checkAndNotify();

        assertThat(mapper.rolesFor("321", scopes())).isEmpty();
        assertThat(mapper.rolesFor("user1", scopes())).contains("only-role");
    }

    @Test
    public void reload_empty_role_user_mapping_if_new_file_erroneous() throws IOException {
        // initialize watcher
        ArgumentCaptor<ResourceWatcher> resourceWatcher = ArgumentCaptor.forClass(ResourceWatcher.class);
        verify(resourceWatcherService).add(resourceWatcher.capture(), any(Frequency.class));
        resourceWatcher.getValue().checkAndNotify();

        assertThat(mapper.rolesFor("321", scopes())).contains("user", "admin");


        // change file
        Files.write(home.getRoot().toPath().resolve("oauth_role_mapping.yml"),
                    ("daljhfsadhfkajdsf").getBytes("UTF-8"),
                    TRUNCATE_EXISTING);

        // manually tell resourceWatcher that file changed
        resourceWatcher.getValue().checkAndNotify();

        assertThat(mapper.rolesFor("321", scopes())).isEmpty();
        assertThat(mapper.rolesFor("user1", scopes())).isEmpty();
    }


    @Before
    public void set_up_role_mapper() throws IOException {
        Files.copy(TestResources.tryResource("oauth_role_mapping.yml").orElseThrow(IllegalStateException::new),
                   home.getRoot().toPath().resolve("oauth_role_mapping.yml"),
                   REPLACE_EXISTING,
                   COPY_ATTRIBUTES);
        mapper = new RefreshableOAuthRoleMapper(new RealmConfig("mapper",
                                                                Settings.builder()
                                                                        .put("type", OAuthRealm.TYPE)
                                                                        .put("files.role_mapping", "oauth_role_mapping.yml")
                                                                        .build(),
                                                                Settings.builder()
                                                                        .put("path.home", home.getRoot().toPath())
                                                                        .build(),
                                                                new ThreadContext(Settings.builder()
                                                                                          .put("type", OAuthRealm.TYPE)
                                                                                          .put("files.role_mapping", "oauth_role_mapping.yml")
                                                                                          .build())),
                                                resourceWatcherService,
                                                onResourceRefresh);
    }

    private Set<String> scopes() {
        return Collections.emptySet();
    }
}
