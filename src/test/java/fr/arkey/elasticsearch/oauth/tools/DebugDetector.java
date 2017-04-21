package fr.arkey.elasticsearch.oauth.tools;

import java.lang.management.ManagementFactory;

public abstract class DebugDetector {

    public static boolean debugging() {
        String jvmArguments = ManagementFactory.getRuntimeMXBean()
                                               .getInputArguments().toString();
        return jvmArguments.contains("-agentlib:jdwp")
                || jvmArguments.contains("-Xrunjdwp")
                || jvmArguments.contains("DEBUG=true");
    }

}
