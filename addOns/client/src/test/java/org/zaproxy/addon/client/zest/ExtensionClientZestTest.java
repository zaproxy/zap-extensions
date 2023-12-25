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
package org.zaproxy.addon.client.zest;

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
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.extension.zest.ExtensionZest;

class ExtensionClientZestTest {
    private ExtensionLoader extensionLoader;
    private ExtensionClientZest extension;

    @BeforeEach
    void setUp() {
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        ExtensionZest extensionZest = mock(ExtensionZest.class);
        given(extensionLoader.getExtension(ExtensionZest.class)).willReturn(extensionZest);

        ExtensionClientIntegration extensionClient = mock(ExtensionClientIntegration.class);
        given(extensionLoader.getExtension(ExtensionClientIntegration.class))
                .willReturn(extensionClient);

        extension = new ExtensionClientZest();
        extension.init();
    }

    private void extensionStarted() {
        extension.hook(mock(ExtensionHook.class));
        extension.start();
    }

    @Test
    void shouldBeUnloadable() {
        assertThat(extension.canUnload(), is(true));
    }

    @Test
    void shouldLoadClientHelper() {
        // Given
        ExtensionZest extensionZest = mock(ExtensionZest.class);
        given(extensionLoader.getExtension(ExtensionZest.class)).willReturn(extensionZest);
        // When
        extensionStarted();
        // Then
        verify(extensionZest).setClientHelper(any());
    }

    @Test
    void shouldRemoveClientHelperOnUnload() {
        // Given
        ExtensionZest extensionZest = mock(ExtensionZest.class);
        given(extensionLoader.getExtension(ExtensionZest.class)).willReturn(extensionZest);
        // When
        extensionStarted();
        extension.unload();
        // Then
        verify(extensionZest).setClientHelper(null);
    }

    @Test
    void shouldLoadClientRecorderHelper() {
        // Given
        ExtensionClientIntegration extensionClient = mock(ExtensionClientIntegration.class);
        given(extensionLoader.getExtension(ExtensionClientIntegration.class))
                .willReturn(extensionClient);
        // When
        extensionStarted();
        // Then
        verify(extensionClient).setClientRecorderHelper(any());
    }

    @Test
    void shouldRemoveClientRecorderHelperOnUnload() {
        // Given
        ExtensionClientIntegration extensionClient = mock(ExtensionClientIntegration.class);
        given(extensionLoader.getExtension(ExtensionClientIntegration.class))
                .willReturn(extensionClient);
        // When
        extensionStarted();
        extension.unload();
        // Then
        verify(extensionClient).setClientRecorderHelper(null);
    }
}
