/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class GitMetadataUnitTest {

    private GitMetadata gitMetadata;

    @BeforeEach
    void setUp() {
        gitMetadata = new GitMetadata(null, 1024);
    }

    @Test
    void shouldValidateCorrectSha1() {
        // Given
        String validSha1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
        // When
        boolean isValid = gitMetadata.validateSHA1(validSha1);
        // Then
        assertThat(isValid, is(true));
    }

    @ParameterizedTest
    @ValueSource(strings = {"short", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd33", ""})
    void shouldInvalidateIncorrectSha1(String invalidSha1) {
        // When
        boolean isValid = gitMetadata.validateSHA1(invalidSha1);
        // Then
        assertThat(isValid, is(false));
    }

    @Test
    void shouldExtractBaseFolderFromStandardPath() {
        // Given
        String path = "http://example.com/.git/index";
        // When
        String base = gitMetadata.getBaseFolder(path);
        // Then
        assertThat(base, is("http://example.com/.git/"));
    }

    @Test
    void shouldExtractBaseFolderFromDeepPath() {
        // Given
        String path = "http://example.com/app/v1/.git/HEAD";
        // When
        String base = gitMetadata.getBaseFolder(path);
        // Then
        assertThat(base, is("http://example.com/app/v1/.git/"));
    }

    @Test
    void shouldReturnNullForNonGitPath() {
        // Given
        String path = "http://example.com/admin/index.php";
        // When
        String base = gitMetadata.getBaseFolder(path);
        // Then
        assertThat(base, is(nullValue()));
    }
}
