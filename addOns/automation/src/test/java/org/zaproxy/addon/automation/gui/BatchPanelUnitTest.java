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
package org.zaproxy.addon.automation.gui;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationParam;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for the construction of {@link BatchPanel}. */
class BatchPanelUnitTest extends TestUtils {

    @TempDir Path dir;

    private ExtensionAutomation ext;
    private AutomationParam param;

    @BeforeEach
    void setUp() {
        ext = mock(ExtensionAutomation.class);
        param = mock(AutomationParam.class);
        when(ext.getParam()).thenReturn(param);
        mockMessages(new ExtensionAutomation());
    }

    @AfterEach
    void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldBeConstructedWithNoDirectory() {
        // When
        BatchPanel panel = new BatchPanel(ext, () -> false, () -> {});
        // Then
        assertThat(panel.getComponentCount() > 0, is(equalTo(true)));
    }

    @Test
    void shouldBeConstructedWithTheLastDirectory() throws IOException {
        // Given
        Files.writeString(dir.resolve("a.yaml"), "x");
        Files.writeString(dir.resolve("b.yaml"), "x");
        when(param.getBatchDirectory()).thenReturn(dir.toString());
        // When
        BatchPanel panel = new BatchPanel(ext, () -> false, () -> {});
        // Then
        assertThat(panel.getComponentCount() > 0, is(equalTo(true)));
        verify(param).setBatchDirectory(dir.toString());
    }

    @Test
    void shouldBeConstructedWithDirectoryWithoutPlans() {
        // Given
        when(param.getBatchDirectory()).thenReturn(dir.toString());
        // When
        BatchPanel panel = new BatchPanel(ext, () -> false, () -> {});
        // Then
        assertThat(panel.getComponentCount() > 0, is(equalTo(true)));
    }
}
