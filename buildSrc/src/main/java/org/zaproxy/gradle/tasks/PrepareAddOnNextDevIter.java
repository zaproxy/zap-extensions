/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.gradle.tasks;

import com.github.zafarkhaja.semver.ParseException;
import com.github.zafarkhaja.semver.Version;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.regex.Pattern;
import org.gradle.api.DefaultTask;
import org.gradle.api.InvalidUserDataException;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.model.ObjectFactory;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;

/**
 * A task that prepares the next development iteration of an add-on.
 *
 * <p>Adds the Unreleased section to the changelog and bumps the version in the build file.
 */
public class PrepareAddOnNextDevIter extends DefaultTask {

    private static final String UNRELEASED_SECTION = "## Unreleased";
    private static final Pattern VERSION_PATTERN = Pattern.compile("## \\[?.+]?.*");

    private final Property<String> currentVersion;
    private final RegularFileProperty buildFile;
    private final RegularFileProperty changelog;

    public PrepareAddOnNextDevIter() {
        ObjectFactory objects = getProject().getObjects();
        this.currentVersion = objects.property(String.class);
        this.buildFile = objects.fileProperty();
        this.changelog = objects.fileProperty();

        setGroup("ZAP Add-On Misc");
        setDescription("Prepares the next development iteration of the add-on.");
    }

    @Input
    public Property<String> getCurrentVersion() {
        return currentVersion;
    }

    @InputFile
    @PathSensitive(PathSensitivity.NONE)
    public RegularFileProperty getBuildFile() {
        return buildFile;
    }

    @InputFile
    @PathSensitive(PathSensitivity.NONE)
    public RegularFileProperty getChangelog() {
        return changelog;
    }

    @TaskAction
    public void prepare() throws IOException {
        Path updatedChangelog = updateChangelog();
        Path updatedBuildFile = updateBuildFile();

        Files.copy(
                updatedChangelog,
                changelog.getAsFile().get().toPath(),
                StandardCopyOption.REPLACE_EXISTING);
        Files.copy(
                updatedBuildFile,
                buildFile.getAsFile().get().toPath(),
                StandardCopyOption.REPLACE_EXISTING);
    }

    private Path updateChangelog() throws IOException {
        Path changelogPath = changelog.getAsFile().get().toPath();
        Path updatedChangelog =
                getTemporaryDir().toPath().resolve("updated-" + changelogPath.getFileName());

        boolean insertUnreleased = true;

        try (BufferedReader reader = Files.newBufferedReader(changelogPath);
                BufferedWriter writer = Files.newBufferedWriter(updatedChangelog)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (insertUnreleased) {
                    if (line.startsWith(UNRELEASED_SECTION)) {
                        throw new InvalidUserDataException(
                                "The changelog already contains the unreleased section.");
                    }

                    if (VERSION_PATTERN.matcher(line).find()) {
                        writer.write(UNRELEASED_SECTION);
                        writer.write("\n\n\n");
                        insertUnreleased = false;
                    }
                }
                writer.write(line);
                writer.write("\n");
            }
        }

        if (insertUnreleased) {
            throw new InvalidUserDataException(
                    "Failed to insert the unreleased section, no version section found.");
        }

        return updatedChangelog;
    }

    private Path updateBuildFile() throws IOException {
        Path buildFilePath = buildFile.getAsFile().get().toPath();
        Path updatedBuildFile =
                getTemporaryDir().toPath().resolve("updated-" + buildFilePath.getFileName());

        String currentVersionLine = versionLine(currentVersion.get());
        String newVersion = bumpVersion(currentVersion.get());

        boolean updateVersion = true;
        try (BufferedReader reader = Files.newBufferedReader(buildFilePath);
                BufferedWriter writer = Files.newBufferedWriter(updatedBuildFile)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (updateVersion && currentVersionLine.equals(line)) {
                    line = versionLine(newVersion);
                    updateVersion = false;
                }
                writer.write(line);
                writer.write("\n");
            }
        }

        if (updateVersion) {
            throw new InvalidUserDataException(
                    "Failed to update the version, current version line not found: "
                            + currentVersionLine);
        }

        return updatedBuildFile;
    }

    private static String versionLine(String version) {
        return "version = \"" + version + "\"";
    }

    private static String bumpVersion(String version) {
        try {
            int currentVersion = Integer.parseInt(version);
            return Integer.toString(++currentVersion);
        } catch (NumberFormatException e) {
            // Ignore, not an integer version.
        }

        try {
            return Version.valueOf(version).incrementMinorVersion().toString();
        } catch (IllegalArgumentException | ParseException e) {
            throw new InvalidUserDataException(
                    "Failed to parse the current version: " + version, e);
        }
    }
}
