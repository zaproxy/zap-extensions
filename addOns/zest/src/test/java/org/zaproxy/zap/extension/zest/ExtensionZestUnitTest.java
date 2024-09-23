/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.script.ScriptWrapper;

/** Unit test for {@link ExtensionZest}. */
class ExtensionZestUnitTest {

    private ExtensionZest extension;

    @BeforeEach
    void setup() {
        extension = new ExtensionZest();
    }

    @Test
    void shouldHandleScriptAddedWithNoEngineName() {
        // Given
        ScriptWrapper sw = mock(ScriptWrapper.class);
        given(sw.getEngineName()).willReturn(null);
        // When/ Then
        assertDoesNotThrow(() -> extension.scriptAdded(sw, false));
    }
}
