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
package org.zaproxy.addon.spider.formhandler;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.spider.ExtensionSpider2;
import org.zaproxy.zap.extension.formhandler.ExtensionFormHandler;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ExtensionSpiderFormHandler}. */
class ExtensionSpiderFormHandlerUnitTest extends TestUtils {

    private ExtensionSpider2 extensionSpider;
    private ExtensionFormHandler extensionFormHandler;
    private ExtensionLoader extensionLoader;
    private ExtensionSpiderFormHandler extension;

    @BeforeEach
    void setUp() {
        extension = new ExtensionSpiderFormHandler();
        mockMessages("org.zaproxy.addon.spider." + Constant.MESSAGES_PREFIX, "spider");

        Model model = mock(Model.class, withSettings().lenient());
        Model.setSingletonForTesting(model);

        extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        Control.initSingletonForTesting(model, extensionLoader);

        extensionSpider = mockLoadedExtension(ExtensionSpider2.class);
        extensionFormHandler = mockLoadedExtension(ExtensionFormHandler.class);
    }

    private <T extends Extension> T mockLoadedExtension(Class<T> clazz) {
        T extension = mock(clazz);
        given(extensionLoader.getExtension(clazz)).willReturn(extension);
        return extension;
    }

    @Test
    void shouldHaveName() {
        assertThat(
                extension.getName(),
                is(equalTo("org.zaproxy.addon.spider.formhandler.ExtensionSpiderFormHandler")));
    }

    @Test
    void shouldHaveUiName() {
        assertThat(extension.getUIName(), is(not(emptyString())));
    }

    @Test
    void shouldHaveDescription() {
        assertThat(extension.getDescription(), is(not(emptyString())));
    }

    @Test
    void shouldHaveExpectedDependencies() {
        assertThat(
                extension.getDependencies(),
                containsInAnyOrder(ExtensionFormHandler.class, ExtensionSpider2.class));
    }

    @Test
    void shouldSetValueGeneratorOnHook() {
        // Given
        ValueGenerator valueGenerator = mock(ValueGenerator.class);
        given(extensionFormHandler.getValueGenerator()).willReturn(valueGenerator);
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        verify(extensionSpider).setValueGenerator(valueGenerator);
    }

    @Test
    void shouldBeUnloadable() {
        assertThat(extension.canUnload(), is(true));
    }

    @Test
    void shouldUnload() {
        // Given / When
        extension.unload();
        // Then
        verify(extensionSpider).setValueGenerator(null);
    }
}
