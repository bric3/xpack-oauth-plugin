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
