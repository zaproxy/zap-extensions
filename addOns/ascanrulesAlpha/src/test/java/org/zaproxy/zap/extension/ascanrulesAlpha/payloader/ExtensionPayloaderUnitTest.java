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
package org.zaproxy.zap.extension.ascanrulesAlpha.payloader;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.ascanrulesAlpha.ExtensionAscanRulesAlpha;
import org.zaproxy.zap.extension.ascanrulesAlpha.PaymentAmountManipulationScanRule;
import org.zaproxy.zap.extension.custompayloads.ExtensionCustomPayloads;
import org.zaproxy.zap.extension.custompayloads.PayloadCategory;
import org.zaproxy.zap.testutils.TestUtils;

class ExtensionPayloaderUnitTest extends TestUtils {

    @Test
    void shouldHaveAName() {
        // Given
        ExtensionPayloader ep = new ExtensionPayloader();
        mockMessages(new ExtensionAscanRulesAlpha());
        // When / Then
        assertThat(ep.getName(), is(equalTo("ExtensionPayloaderAscanRulesAlpha")));
        assertThat(ep.getUIName(), is(equalTo("Active Scan Rules Alpha Custom Payloads")));
    }

    @Test
    void shouldBeUnloadable() {
        // Given
        ExtensionPayloader ep = new ExtensionPayloader();
        // When / Then
        assertThat(ep.canUnload(), is(equalTo(true)));
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Test
    void shouldHandleExpectedCategoriesOnHookAndUnload() {
        // Given
        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        ExtensionPayloader ep = new ExtensionPayloader();
        ExtensionHook eh = mock(ExtensionHook.class);
        ExtensionCustomPayloads ecp = mock(ExtensionCustomPayloads.class);
        given(extensionLoader.getExtension(ExtensionCustomPayloads.class)).willReturn(ecp);
        ArgumentCaptor<PayloadCategory> inCategories =
                ArgumentCaptor.forClass(PayloadCategory.class);
        ArgumentCaptor<PayloadCategory> outCategories =
                ArgumentCaptor.forClass(PayloadCategory.class);
        ArgumentCaptor<Supplier> moneyWordsSuppliers = ArgumentCaptor.forClass(Supplier.class);
        try (MockedStatic<PaymentAmountManipulationScanRule> moneyWordsRule =
                mockStatic(PaymentAmountManipulationScanRule.class)) {
            // When
            ep.hook(eh);
            ep.unload();
            // Then
            moneyWordsRule.verify(
                    () ->
                            PaymentAmountManipulationScanRule.setMoneyWordsProvider(
                                    moneyWordsSuppliers.capture()),
                    times(2));
            // The supplier should be set null on unload, second invocation
            Supplier<?> outMoneyWordsSupplier = moneyWordsSuppliers.getAllValues().get(1);
            assertThat(outMoneyWordsSupplier, is(equalTo(null)));

            verify(ecp, times(1)).addPayloadCategory(inCategories.capture());
            PayloadCategory inCategory1 = inCategories.getAllValues().get(0);

            verify(ecp, times(1)).removePayloadCategory(outCategories.capture());
            PayloadCategory outCategory1 = outCategories.getAllValues().get(0);

            assertThat(inCategory1.getName(), is(equalTo(outCategory1.getName())));
            assertThat(
                    inCategory1.getName(),
                    is(equalTo(PaymentAmountManipulationScanRule.MONEY_WORDS_PAYLOAD_CATEGORY)));
            Supplier<Iterable<String>> inSupplier = moneyWordsSuppliers.getAllValues().get(0);
            assertThat(
                    toList(inSupplier.get()),
                    is(equalTo(toList(inCategory1.getPayloadsIterator()))));
        }
    }

    private static List<String> toList(Iterable<String> iterable) {
        List<String> list = new ArrayList<>();
        iterable.forEach(list::add);
        return list;
    }
}
