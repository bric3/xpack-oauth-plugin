package fr.arkey.elasticsearch.oauth.realm;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import com.google.common.collect.ImmutableSetMultimap;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.shield.ShieldPlugin;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.shield.authc.support.RefreshListener;
import org.elasticsearch.watcher.FileChangesListener;
import org.elasticsearch.watcher.FileWatcher;
import org.elasticsearch.watcher.ResourceWatcherService;

import static java.util.Objects.requireNonNull;

/**
 * A refreshable role user mapper service.
 *
 * It will read the role mapping file defined in this setting : {@code shield.authc.realms.oauth.files.role_mapping}
 * and watch for any change on this file.
 *
 * Any error in this file will have the same effect of an empty file.
 */
public class RefreshableOAuthRoleMapper {
    private final ESLogger logger;
    private final RefreshListener listener;
    private final Path oauthRoleMappingFile;
    private volatile ImmutableSetMultimap<String, String> refreshableRoleMapping;

    /**
     * Build and configures a refreshable role user mapper service that will read
     * the role mapping file defined in this setting : {@code shield.authc.realms.oauth.files.role_mapping}
     * and watch for any change on this file.
     *
     * @param realmConfig the configuration to create the realm with
     * @param watcherService the elasticsearch watcher service
     * @param onRoleMappingChange the listener that will be notified on the file change
     */
    public RefreshableOAuthRoleMapper(RealmConfig realmConfig,
                                      ResourceWatcherService watcherService,
                                      RefreshListener onRoleMappingChange) {

        this.logger = requireNonNull(realmConfig).logger(this.getClass());
        this.listener = requireNonNull(onRoleMappingChange);

        oauthRoleMappingFile = resolveRoleMappingFile(realmConfig.settings(), realmConfig.env());
        loadRoleMappingFile();
        configureAndStartRoleMappingFileWatcher(realmConfig,
                                                requireNonNull(watcherService),
                                                ResourceWatcherService.Frequency.HIGH,
                                                this::loadRoleMappingFile);
    }

    /**
     * Identify the roles for the given user id.
     *
     * Note scopes is not yet supported, it may come as a later improvement.
     *
     * @param userId The user id to match
     * @param scopes The scopes, ignored at this time
     * @return The roles for this user or nothing if not found
     */
    public String[] rolesFor(String userId, Set<String> scopes) {
        return refreshableRoleMapping.get(userId).toArray(new String[0]);
    }

    @SuppressWarnings("unchecked")
    private ImmutableSetMultimap<String, String> parseRoleMappingFile(Path oauthRoleMappingFile) throws IOException {
        logger.info("Loading OAuth role mapping file [{}]", oauthRoleMappingFile);
        try (BufferedInputStream roleMappingFIS = new BufferedInputStream(Files.newInputStream(oauthRoleMappingFile))) {
            Settings oauthMappingSettings = Settings.builder()
                                                    .loadFromStream(oauthRoleMappingFile.getFileName().toString(),
                                                                    roleMappingFIS)
                                                    .build();

            ImmutableSetMultimap.Builder<String, String> builder = ImmutableSetMultimap.builder();
            oauthMappingSettings.getAsStructuredMap()
                                .forEach((role, userIds) -> builder.putAll(role, (List<String>) userIds));
            ImmutableSetMultimap<String, String> roleUserIds = builder.build();

            return roleUserIds.inverse();
        }
    }

    private void configureAndStartRoleMappingFileWatcher(RealmConfig config,
                                                         ResourceWatcherService watcherService,
                                                         ResourceWatcherService.Frequency frequency,
                                                         Runnable onFileChanged) {
        FileWatcher watcher = new FileWatcher(oauthRoleMappingFile.getParent());
        watcher.addListener(new FileChangesListener() {
            @Override
            public void onFileCreated(Path file) {
                this.onFileChanged(file);
            }

            @Override
            public void onFileDeleted(Path file) {
                this.onFileChanged(file);
            }

            @Override
            public void onFileChanged(Path file) {
                if (file.equals(oauthRoleMappingFile)) {
                    logger.info("OAuth role mappings file [{}] changed for realm [{}/{}]. updating mappings...",
                                file.toAbsolutePath(),
                                OAuthRealm.TYPE,
                                config.name());
                    onFileChanged.run();
                }
            }
        });

        try {
            watcherService.add(watcher, frequency);
        } catch (IOException e) {
            throw new ElasticsearchException("failed to start file watcher for role mapping file [" +
                                             oauthRoleMappingFile.toAbsolutePath()
                                             + "]"
            );
        }
    }

    private void loadRoleMappingFile() {
        try {
            refreshableRoleMapping = parseRoleMappingFile(oauthRoleMappingFile);
        } catch (Throwable throwable) {
            logger.error("failed to parse role mappings file [{}]. skipping/removing all mappings...",
                         throwable,
                         oauthRoleMappingFile.toAbsolutePath());
            refreshableRoleMapping = ImmutableSetMultimap.of();
        } finally {
            listener.onRefresh();
        }
    }

    private static Path resolveRoleMappingFile(Settings settings, Environment env) {
        // es.shield.authc.realms.oauth.files.role_mapping
        String location = settings.get("files.role_mapping");
        return location == null ?
               ShieldPlugin.resolveConfigFile(env, "oauth_role_mapping.yml") : // config_dir/shield/oauth_role_mapping.yml
               env.binFile().getParent().resolve(location);
    }
}
