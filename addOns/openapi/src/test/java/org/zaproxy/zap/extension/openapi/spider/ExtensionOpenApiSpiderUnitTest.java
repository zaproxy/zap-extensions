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
package org.zaproxy.zap.extension.openapi.spider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.spider.ExtensionSpider2;
import org.zaproxy.zap.extension.openapi.ExtensionOpenApi;
import org.zaproxy.zap.testutils.TestUtils;

class ExtensionOpenApiSpiderUnitTest extends TestUtils {

    private ExtensionLoader extensionLoader;
    private ExtensionOpenApiSpider extension;

    @BeforeEach
    void setUp() {
        extension = new ExtensionOpenApiSpider();
        extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
    }

    @Test
    void shouldAddCustomParserOnHook() {
        // Given
        ExtensionSpider2 extensionSpider = mock(ExtensionSpider2.class);
        given(extensionLoader.getExtension(ExtensionSpider2.class)).willReturn(extensionSpider);
        ExtensionOpenApi extensionOpenApi = mock(ExtensionOpenApi.class);
        given(extensionLoader.getExtension(ExtensionOpenApi.class)).willReturn(extensionOpenApi);
        // When
        extension.hook(null);
        // Then
        verify(extensionSpider).addCustomParser(any());
    }

    @Test
    void shouldBeUnloadable() {
        assertThat(extension.canUnload(), is(true));
    }

    @Test
    void shouldRemoveCustomParserOnUnload() {
        // Given
        ExtensionSpider2 extensionSpider = mock(ExtensionSpider2.class);
        given(extensionLoader.getExtension(ExtensionSpider2.class)).willReturn(extensionSpider);
        // When
        extension.unload();
        // Then
        verify(extensionSpider).removeCustomParser(any());
    }
}
