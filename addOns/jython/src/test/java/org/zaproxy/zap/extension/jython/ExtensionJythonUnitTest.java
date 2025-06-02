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
package org.zaproxy.zap.extension.jython;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.script.ExtensionScript;

/** Unit test for {@link ExtensionJython}. */
class ExtensionJythonUnitTest {

    private Model model;
    private ExtensionLoader extensionLoader;
    private ExtensionScript extensionScript;

    private ExtensionJython extension;

    @BeforeEach
    void setUp() {
        model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(model, extensionLoader);

        extensionScript =
                mock(ExtensionScript.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extensionScript);

        extension = new ExtensionJython();
    }

    @Test
    void shouldRegisterEngineOnHook() {
        // Given / When
        extension.hook(mock(ExtensionHook.class));
        // Then
        verify(extensionScript).registerScriptEngineWrapper(any(JythonEngineWrapper.class));
    }

    @Test
    void shouldBeUnloadable() {
        assertThat(extension.canUnload(), is(true));
    }

    @Test
    void shouldRemoveEngineOnUnload() {
        // Given
        extension.hook(mock(ExtensionHook.class));
        // When
        extension.unload();
        // Then
        verify(extensionScript).removeScriptEngineWrapper(any(JythonEngineWrapper.class));
    }
}
