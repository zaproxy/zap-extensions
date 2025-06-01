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
package org.zaproxy.zap.extension.pscanrules.payloader;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.custompayloads.ExtensionCustomPayloads;
import org.zaproxy.zap.extension.custompayloads.PayloadCategory;
import org.zaproxy.zap.extension.pscanrules.ApplicationErrorScanRule;
import org.zaproxy.zap.extension.pscanrules.ExtensionPscanRules;
import org.zaproxy.zap.extension.pscanrules.InformationDisclosureSuspiciousCommentsScanRule;
import org.zaproxy.zap.extension.pscanrules.UsernameIdorScanRule;
import org.zaproxy.zap.testutils.TestUtils;

class ExtensionPayloaderUnitTest extends TestUtils {

    @Test
    void shouldHaveAName() {
        // Given
        ExtensionPayloader ep = new ExtensionPayloader();
        mockMessages(new ExtensionPscanRules());
        // When / Then
        assertThat(ep.getName(), is(equalTo("ExtensionPayloaderPscanRulesRelease")));
        assertThat(ep.getUIName(), is(equalTo("Passive Scan Rules Release Custom Payloads")));
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
        MockedStatic<UsernameIdorScanRule> idorRule = mockStatic(UsernameIdorScanRule.class);
        MockedStatic<ApplicationErrorScanRule> errorRule =
                mockStatic(ApplicationErrorScanRule.class);
        MockedStatic<InformationDisclosureSuspiciousCommentsScanRule> commentRule =
                mockStatic(InformationDisclosureSuspiciousCommentsScanRule.class);
        ArgumentCaptor<Supplier> idorSuppliers = ArgumentCaptor.forClass(Supplier.class);
        ArgumentCaptor<Supplier> errorSuppliers = ArgumentCaptor.forClass(Supplier.class);
        ArgumentCaptor<Supplier> commentSuppliers = ArgumentCaptor.forClass(Supplier.class);
        // When
        ep.hook(eh);
        ep.unload();
        // Then
        idorRule.verify(
                () -> UsernameIdorScanRule.setPayloadProvider(idorSuppliers.capture()), times(2));
        // The supplier should be set null on unload, second invocation
        Supplier<?> outIdorSupplier = idorSuppliers.getAllValues().get(1);
        assertThat(outIdorSupplier, is(equalTo(null)));

        errorRule.verify(
                () -> ApplicationErrorScanRule.setPayloadProvider(errorSuppliers.capture()),
                times(2));
        // The supplier should be set null on unload, second invocation
        Supplier<?> outErrorSupplier = errorSuppliers.getAllValues().get(1);
        assertThat(outErrorSupplier, is(equalTo(null)));

        commentRule.verify(
                () ->
                        InformationDisclosureSuspiciousCommentsScanRule.setPayloadProvider(
                                commentSuppliers.capture()),
                times(2));
        // The supplier should be set null on unload, second invocation
        Supplier<?> outCommentSupplier = commentSuppliers.getAllValues().get(1);
        assertThat(outCommentSupplier, is(equalTo(null)));

        verify(ecp, times(3)).addPayloadCategory(inCategories.capture());
        PayloadCategory inCategory1 = inCategories.getAllValues().get(0);
        PayloadCategory inCategory2 = inCategories.getAllValues().get(1);
        PayloadCategory inCategory3 = inCategories.getAllValues().get(2);

        verify(ecp, times(3)).removePayloadCategory(outCategories.capture());
        PayloadCategory outCategory1 = outCategories.getAllValues().get(0);
        PayloadCategory outCategory2 = outCategories.getAllValues().get(1);
        PayloadCategory outCategory3 = outCategories.getAllValues().get(2);

        assertThat(inCategory1.getName(), is(equalTo(outCategory1.getName())));
        assertThat(inCategory2.getName(), is(equalTo(outCategory2.getName())));
        assertThat(inCategory3.getName(), is(equalTo(outCategory3.getName())));
    }
}
