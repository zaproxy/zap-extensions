/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium.internal;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.selenium.ProfileManager;
import org.zaproxy.zap.utils.Stats;

public class FirefoxProfileManager implements ProfileManager {

    private static final String PROFILE_NAME_REGEX = "^\\w{8}\\.";
    private static final String MACOS_DIR = "/Library/Application Support/Firefox/Profiles";
    private static final String WINDOWS_DIR = "/Mozilla/Firefox/Profiles";
    private static final String LINUX_DIR = "/.mozilla/firefox";

    private static final Logger LOGGER = LogManager.getLogger(FirefoxProfileManager.class);

    private Path profileDirectory;
    private List<String> profiles;
    private Runtime runtime = Runtime.getRuntime();

    private Path getProfilesDirectory() {
        if (profileDirectory == null) {
            if (Constant.isMacOsX()) {
                profileDirectory = Paths.get(System.getProperty("user.home"), MACOS_DIR);
            } else if (Constant.isWindows()) {
                profileDirectory = Paths.get(System.getenv("APPDATA"), WINDOWS_DIR);
            } else if (Constant.isLinux()) {
                profileDirectory = Paths.get(System.getProperty("user.home"), LINUX_DIR);
            } else {
                Stats.incCounter(
                        "stats.selenium.profile.dir.failure." + System.getProperty("os.name"));
                LOGGER.error(
                        "Do not know how to find Firefox directory for {}",
                        System.getProperty("os.name"));
            }
        }
        if (!profileDirectory.toFile().isDirectory()) {
            profileDirectory = null;
        }
        return profileDirectory;
    }

    protected void setProfilesDirectory(Path dir) {
        this.profileDirectory = dir;
    }

    /**
     * Only for use in unit tests
     *
     * @param runtime
     */
    protected void setRuntime(Runtime runtime) {
        this.runtime = runtime;
    }

    @Override
    public List<String> getProfiles() {
        if (profiles == null) {
            /*
             * This is a quick and dirty implementation ;)
             * The correct way to do this would be to parse the firefox.ini file e.g. using Apache Commons INIConfiguration.
             * However this should work for the key initial usecase and we can implement correctly if there is demand.
             */
            Path profileDir = getProfilesDirectory();
            if (profileDir == null) {
                return Collections.emptyList();
            }
            // Firefox profiles are 8 random characters followed by a dot and then the profile name
            Pattern p = Pattern.compile(PROFILE_NAME_REGEX);
            profiles =
                    Arrays.stream(profileDir.toFile().list())
                            .filter(n -> new File(getProfilesDirectory().toFile(), n).isDirectory())
                            .filter(p.asPredicate())
                            .map(s -> s.substring(9))
                            .collect(Collectors.toList());
            Collections.sort(profiles);
        }
        return List.copyOf(profiles);
    }

    @Override
    public Path getProfileDirectory(String profileName) {
        Path profileDir = getProfilesDirectory();
        if (profileDir == null) {
            return null;
        }
        Pattern p = Pattern.compile(PROFILE_NAME_REGEX + profileName + "$");
        Optional<String> fullName =
                Arrays.stream(profileDir.toFile().list()).filter(p.asPredicate()).findFirst();
        if (fullName.isPresent()) {
            return profileDir.resolve(fullName.get());
        }
        return null;
    }

    @Override
    public Path getOrCreateProfile(String profileName) throws IOException {
        Path dir = this.getProfileDirectory(profileName);
        if (dir != null) {
            return dir;
        }
        FirefoxOptions firefoxOptions = new FirefoxOptions();
        String path = firefoxOptions.getBinary().getPath();

        Process ps = runtime.exec(new String[] {path, "-CreateProfile", profileName});

        try {
            ps.waitFor();
        } catch (InterruptedException e) {
            // Ignore
        }
        // Reset so that we reread them next time
        this.profiles = null;

        Path profileDir = this.getProfileDirectory(profileName);
        if (profileDir != null) {
            Stats.incCounter(
                    "stats.selenium.profile.create.success." + System.getProperty("os.name"));
        } else {
            Stats.incCounter(
                    "stats.selenium.profile.create.failure." + System.getProperty("os.name"));
        }
        return profileDir;
    }
}
