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

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.model.ObjectFactory;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;

/**
 * A task that extracts the changes from the latest version (unreleased or not) from a changelog (in
 * Keep a Changelog format).
 */
public class ExtractLatestChangesChangelog extends DefaultTask {

    private static final int CHANGELOG_CHUNK_SIZE = 20_000;

    private static final Pattern VERSION_PATTERN = Pattern.compile("(?m)^## \\[?.+]?.*\\R");
    private static final Pattern VERSION_LINK_PATTERN = Pattern.compile("(?m)^\\[.+]:");

    private final RegularFileProperty changelog;
    private final RegularFileProperty latestChanges;

    public ExtractLatestChangesChangelog() {
        ObjectFactory objects = getProject().getObjects();
        changelog = objects.fileProperty();
        latestChanges = objects.fileProperty();
    }

    @InputFile
    @PathSensitive(PathSensitivity.NONE)
    public RegularFileProperty getChangelog() {
        return changelog;
    }

    @OutputFile
    public RegularFileProperty getLatestChanges() {
        return latestChanges;
    }

    @TaskAction
    public void extract() throws IOException {
        try (Writer writer = Files.newBufferedWriter(latestChanges.get().getAsFile().toPath())) {
            writer.write(getChanges(changelog.get().getAsFile().toPath()).trim());
        }
    }

    private String getChanges(Path changelog) throws IOException {
        return extractChangesLatestVersion(readChunk(changelog));
    }

    private static String readChunk(Path changelog) throws IOException {
        char[] chars = new char[CHANGELOG_CHUNK_SIZE];
        int n;
        try (Reader reader = Files.newBufferedReader(changelog)) {
            n = reader.read(chars);
        }
        if (n == -1) {
            throw new IOException("Failed to read any characters from: " + changelog);
        }
        return new String(chars, 0, n);
    }

    private String extractChangesLatestVersion(String contents) {
        Matcher matcher = VERSION_PATTERN.matcher(contents);
        if (!matcher.find()) {
            throw new IllegalArgumentException(
                    String.format(
                            "No version matching '%1s' was found in changelog:%n%2s",
                            VERSION_PATTERN, contents));
        }
        int changesStart = matcher.end();
        int changesEnd = contents.length();
        if (matcher.find()) {
            changesEnd = matcher.start();
        } else {
            getLogger().debug("Second version not found, using version link.");
            matcher = VERSION_LINK_PATTERN.matcher(contents);
            if (matcher.find()) {
                changesEnd = matcher.start();
            } else {
                getLogger().debug("Version link not found, defaulting to end of contents.");
            }
        }
        return contents.substring(changesStart, changesEnd);
    }
}
