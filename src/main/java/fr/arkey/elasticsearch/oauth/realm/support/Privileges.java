package fr.arkey.elasticsearch.oauth.realm.support;

import java.security.AccessController;
import java.security.PrivilegedAction;
import org.elasticsearch.SpecialPermission;

public class Privileges {
    public static <T> T pluginPrivileges(PrivilegedAction<T> privilegedAction) {
        // This will add special permissions need by the plugin.
        // Check the 'plugin-security.policy' file.
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        return AccessController.doPrivileged(privilegedAction);
    }
}
