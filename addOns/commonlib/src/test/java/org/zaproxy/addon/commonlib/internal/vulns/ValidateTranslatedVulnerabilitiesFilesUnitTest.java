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
package org.zaproxy.addon.commonlib.internal.vulns;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.testutils.TestUtils;

/** Validates that the translated vulnerabilities files have the expected content. */
class ValidateTranslatedVulnerabilitiesFilesUnitTest extends TestUtils {

    private static final String FILE_NAME = "vulnerabilities";
    private static final String FILE_EXTENSION = ".xml";
    private static final String SOURCE_FILE = FILE_NAME + FILE_EXTENSION;

    private static Map<String, Vulnerability> source;
    private static List<Path> translations;

    @BeforeAll
    static void setUp() throws Exception {
        Path sourceFile =
                Paths.get(
                        ValidateTranslatedVulnerabilitiesFilesUnitTest.class
                                .getResource(SOURCE_FILE)
                                .toURI());
        Path dir = sourceFile.getParent();
        source = loadFile(sourceFile);
        translations = new ArrayList<>();
        try (var stream = Files.newDirectoryStream(dir)) {
            stream.forEach(
                    e -> {
                        String fileName = e.getFileName().toString();
                        if (fileName.startsWith(FILE_NAME) && fileName.endsWith(FILE_EXTENSION)) {
                            translations.add(e);
                        }
                    });
        }
        translations.remove(sourceFile);
    }

    @Test
    @Disabled("Until next crowdin sync")
    void shouldLoadAllVulnerabilitiesFilesAvailable() {
        processTranslations(
                (fileName, source, translated) ->
                        assertThat(fileName, translated.values(), hasSize(source.size())),
                (fileName, id, source, translated) -> {
                    assertThat("Missing " + id + " in " + fileName, translated, is(notNullValue()));
                    assertThat(
                            "Wrong number of references in " + fileName + " for " + id,
                            translated.getReferences(),
                            hasSize(source.getReferences().size()));
                });
    }

    @Test
    @Disabled("Only needed when doing content changes, which does not happen often.")
    void shouldHaveExpectedContentForAllVulnerabilitiesFilesAvailable() throws Exception {
        processTranslations(
                (fileName, source, translated) -> {},
                (fileName, id, source, translated) -> {
                    assertFieldContents(
                            fileName, id, source, translated, "Name", Vulnerability::getName);
                    assertFieldContents(
                            fileName,
                            id,
                            source,
                            translated,
                            "Description",
                            Vulnerability::getDescription);
                    assertFieldContents(
                            fileName,
                            id,
                            source,
                            translated,
                            "Solution",
                            Vulnerability::getSolution);
                });
    }

    private static void assertFieldContents(
            String fileName,
            String id,
            Vulnerability source,
            Vulnerability translated,
            String fieldName,
            Function<Vulnerability, String> function) {
        String valueSource = function.apply(source);
        String valueTranslated = function.apply(translated);
        if (valueSource == null) {
            assertThat(
                    fieldName + " should be null for " + id + " in " + fileName,
                    valueTranslated,
                    is(nullValue()));
        } else if (valueSource.isEmpty()) {
            assertThat(
                    fieldName + " should be empty for " + id + " in " + fileName,
                    valueTranslated,
                    is(emptyString()));
        } else {
            assertThat(
                    fieldName + " should be non-empty for " + id + " in " + fileName,
                    valueTranslated,
                    is(not(emptyString())));
        }
    }

    private static String getFileName(Path file) {
        return file.getFileName().toString();
    }

    private static Map<String, Vulnerability> loadFile(Path file) {
        try (var is = Files.newInputStream(file)) {
            return DefaultVulnerabilities.loadVulnerabilities(is).getMap();
        } catch (IOException e) {
            fail("File " + getFileName(file) + " is not wellformed: " + e.getMessage(), e);
            return null;
        }
    }

    private static void processTranslations(AllValidator all, EntryValidator entry) {
        for (Path file : translations) {
            Map<String, Vulnerability> translated = loadFile(file);
            String fileName = getFileName(file);
            all.validate(fileName, source, translated);
            source.forEach(
                    (id, source) -> entry.validate(fileName, id, source, translated.get(id)));
        }
    }

    private interface AllValidator {

        void validate(
                String fileName,
                Map<String, Vulnerability> source,
                Map<String, Vulnerability> translated);
    }

    private interface EntryValidator {

        void validate(String fileName, String id, Vulnerability source, Vulnerability translated);
    }
}
