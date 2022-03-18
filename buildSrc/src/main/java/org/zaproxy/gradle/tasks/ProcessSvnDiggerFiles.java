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

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.ConfigurableFileTree;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.tasks.IgnoreEmptyDirectories;
import org.gradle.api.tasks.InputFiles;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.SkipWhenEmpty;
import org.gradle.api.tasks.TaskAction;

public class ProcessSvnDiggerFiles extends DefaultTask {

    private static final String SVNDIGGER_DIR = "svndigger";
    private static final String SVNDIGGER_PREFIX = SVNDIGGER_DIR + "-";
    private static final String DIRBUSTER_DIR = "dirbuster";
    private static final String LICENCE_FILE_NAME = "Licence.txt";
    private static final String README_FILE_NAME = "ReadMe.txt";

    private final ConfigurableFileTree sourceFiles;
    private final DirectoryProperty outputDir;

    public ProcessSvnDiggerFiles() {
        this.sourceFiles = getProject().fileTree(getProject().file("src/main/" + SVNDIGGER_DIR));
        this.sourceFiles.exclude(LICENCE_FILE_NAME, README_FILE_NAME);
        this.outputDir = getProject().getObjects().directoryProperty();
    }

    @InputFiles
    @SkipWhenEmpty
    @IgnoreEmptyDirectories
    public ConfigurableFileTree getSourceFiles() {
        return sourceFiles;
    }

    @OutputDirectory
    public DirectoryProperty getOutputDir() {
        return outputDir;
    }

    @TaskAction
    public void process() throws IOException {
        Path srcDir = sourceFiles.getDir().toPath();
        Path dirbusterDir = outputDir.get().getAsFile().toPath().resolve(DIRBUSTER_DIR);
        Path svndiggerDir = dirbusterDir.resolve(SVNDIGGER_DIR);

        getProject().delete(dirbusterDir.toFile());
        Files.createDirectories(svndiggerDir);
        Files.copy(srcDir.resolve(LICENCE_FILE_NAME), svndiggerDir.resolve(LICENCE_FILE_NAME));
        Files.copy(srcDir.resolve(README_FILE_NAME), svndiggerDir.resolve(README_FILE_NAME));

        processFiles(srcDir, sourceFiles.getFiles(), dirbusterDir);
    }

    private static void processFiles(Path srcDir, Set<File> files, Path outputDir)
            throws IOException {
        for (File file : files) {
            String name =
                    SVNDIGGER_PREFIX
                            + srcDir.relativize(file.toPath())
                                    .toString()
                                    .replace(FileSystems.getDefault().getSeparator(), "-");
            Files.copy(file.toPath(), outputDir.resolve(name));
        }
    }
}
