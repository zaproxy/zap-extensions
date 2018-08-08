/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.groovy;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.URL;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import groovy.lang.GroovyClassLoader;

/** Verifies that the script templates are parsed without errors. */
public class VerifyScriptTemplates {

    @Test
    public void shouldParseTemplates() throws Exception {
        // Given
        List<Path> templates = getScriptTemplates(".groovy");
        try (GroovyClassLoader groovyCl = new GroovyClassLoader()) {
            for (Path template : templates) {
                // When / Then
                groovyCl.parseClass(template.toFile());
            }
        }
    }

    private static List<Path> getScriptTemplates(String extension) throws Exception {
        String dirName = "files/scripts/templates";
        URL dirPath = VerifyScriptTemplates.class.getResource(dirName);
        assertThat("Directory " + dirName + " not found on the classpath.", dirPath, is(not(nullValue())));

        List<Path> templates = new ArrayList<>();
        Files.walkFileTree(Paths.get(dirPath.toURI()), new SimpleFileVisitor<Path>() {

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                String fileName = file.getFileName().toString();
                if (fileName.endsWith(extension) && !isExcluded(file)) {
                    templates.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });

        assertThat("No templates found in: " + dirPath, templates, is(not(empty())));

        return templates;
    }

    private static boolean isExcluded(Path template) {
        String parentDir = template.getParent().getFileName().toString();
        // XXX Validate when the add-ons Fuzzer and Script Console are included in the test classpath.
        return parentDir.equals("httpfuzzerprocessor") || parentDir.equals("extender");
    }
}