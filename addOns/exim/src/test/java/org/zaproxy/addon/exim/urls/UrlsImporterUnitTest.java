/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.exim.urls;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.File;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link UrlsImporter}. */
class UrlsImporterUnitTest {

    @BeforeAll
    static void setup() {
        Constant.messages = mock(I18N.class);
    }

    @AfterAll
    static void cleanup() {
        Constant.messages = null;
    }

    @Test
    void shouldBeFailureIfFileNotFound(@TempDir Path dir) throws Exception {
        // Given
        File file = dir.resolve("missing.txt").toFile();
        // When
        UrlsImporter importer = new UrlsImporter(file);
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
    }

    @Test
    void shouldCompleteListenerIfFileNotFound(@TempDir Path dir) throws Exception {
        // Given
        File file = dir.resolve("missing.txt").toFile();
        ProgressPaneListener listener = mock(ProgressPaneListener.class);
        // When
        UrlsImporter importer = new UrlsImporter(file, listener);
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
        verify(listener).completed();
    }
}
