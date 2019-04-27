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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.LocalDate;
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
 * A task that prepares the release of an add-on.
 *
 * <p>Replaces the Unreleased section and adds the release link to the changelog.
 */
public class PrepareAddOnRelease extends DefaultTask {

    private static final Pattern VERSION_LINK_PATTERN = Pattern.compile("\\[.+]:");

    private final Property<String> version;
    private final Property<String> releaseLink;
    private final Property<String> releaseDate;
    private final RegularFileProperty changelog;

    public PrepareAddOnRelease() {
        ObjectFactory objects = getProject().getObjects();
        this.version = objects.property(String.class);
        this.releaseLink = objects.property(String.class);
        this.releaseDate = objects.property(String.class).value(LocalDate.now().toString());
        this.changelog = objects.fileProperty();

        setGroup("ZAP Add-On Misc");
        setDescription("Prepares the release of the add-on.");
    }

    @Input
    public Property<String> getVersion() {
        return version;
    }

    @Input
    public Property<String> getReleaseLink() {
        return releaseLink;
    }

    @Input
    public Property<String> getReleaseDate() {
        return releaseDate;
    }

    @InputFile
    @PathSensitive(PathSensitivity.NONE)
    public RegularFileProperty getChangelog() {
        return changelog;
    }

    @TaskAction
    public void prepare() throws IOException {
        Path changelogPath = changelog.getAsFile().get().toPath();
        Path updatedChangelog =
                getTemporaryDir().toPath().resolve("updated-" + changelogPath.getFileName());

        boolean insertLink = true;
        boolean replaceUnreleased = true;

        try (BufferedReader reader = Files.newBufferedReader(changelogPath);
                BufferedWriter writer = Files.newBufferedWriter(updatedChangelog)) {
            boolean lastLineEmpty = false;
            String line;
            while ((line = reader.readLine()) != null) {
                if (insertLink && VERSION_LINK_PATTERN.matcher(line).find()) {
                    writeReleaseLink(writer);
                    writer.write("\n");
                    insertLink = false;
                } else if (replaceUnreleased && line.startsWith("## Unreleased")) {
                    line = "## [" + version.get() + "] - " + releaseDate.get();
                    replaceUnreleased = false;
                }
                writer.write(line);
                writer.write("\n");
                lastLineEmpty = line.isEmpty();
            }

            if (insertLink) {
                if (!lastLineEmpty) {
                    writer.write("\n");
                }
                writeReleaseLink(writer);
            }
        }

        if (replaceUnreleased) {
            throw new InvalidUserDataException("Changelog does not have the unreleased section.");
        }

        Files.copy(updatedChangelog, changelogPath, StandardCopyOption.REPLACE_EXISTING);
    }

    private void writeReleaseLink(Writer writer) throws IOException {
        writer.write("[" + version.get() + "]: " + releaseLink.get());
    }
}
