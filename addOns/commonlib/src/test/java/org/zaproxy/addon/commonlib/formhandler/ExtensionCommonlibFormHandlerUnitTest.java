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
package org.zaproxy.addon.commonlib.formhandler;

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
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.zap.extension.formhandler.ExtensionFormHandler;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ExtensionCommonlibFormHandler}. */
class ExtensionCommonlibFormHandlerUnitTest extends TestUtils {

    private ExtensionCommonlib extensionCommonlib;
    private ExtensionFormHandler extensionFormHandler;
    private ExtensionCommonlibFormHandler extension;

    @BeforeEach
    void setUp() {
        extension = new ExtensionCommonlibFormHandler();
        mockMessages(
                "org.zaproxy.addon.commonlib.resources." + Constant.MESSAGES_PREFIX, "commonlib");

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Model.setSingletonForTesting(model);

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(model, extensionLoader);

        extensionCommonlib = mockLoadedExtension(extensionLoader, ExtensionCommonlib.class);
        extensionFormHandler = mockLoadedExtension(extensionLoader, ExtensionFormHandler.class);
    }

    private static <T extends Extension> T mockLoadedExtension(
            ExtensionLoader extensionLoader, Class<T> clazz) {
        T extension = mock(clazz);
        given(extensionLoader.getExtension(clazz)).willReturn(extension);
        return extension;
    }

    @Test
    void shouldHaveName() {
        assertThat(
                extension.getName(),
                is(
                        equalTo(
                                "org.zaproxy.addon.commonlib.formhandler.ExtensionCommonlibFormHandler")));
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
                containsInAnyOrder(ExtensionFormHandler.class, ExtensionCommonlib.class));
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
        verify(extensionCommonlib).setCustomValueGenerator(valueGenerator);
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
        verify(extensionCommonlib).setCustomValueGenerator(null);
    }
}
