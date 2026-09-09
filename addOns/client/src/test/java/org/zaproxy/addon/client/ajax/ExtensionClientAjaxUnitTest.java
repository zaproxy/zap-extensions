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
package org.zaproxy.addon.client.ajax;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.spider.ClientSpiderOptions;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate.Status;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.testutils.TestUtils;

class ExtensionClientAjaxUnitTest extends TestUtils {

    private ExtensionLoader extensionLoader;
    private ExtensionClientAjax extension;
    private API api;

    @BeforeEach
    void setUp() {
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionClientIntegration extClient =
                mock(
                        ExtensionClientIntegration.class,
                        withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionClientIntegration.class)).willReturn(extClient);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);

        mockMessages(new ExtensionClientIntegration());

        ClientSpiderOptions clientSpiderOptions = new ClientSpiderOptions();
        given(extClient.getClientSpiderParam()).willReturn(clientSpiderOptions);

        api = mock(API.class);
        extension = new ExtensionClientAjax();
    }

    private void hookExtension() {
        try (MockedStatic<API> apiStatic = mockStatic(API.class)) {
            apiStatic.when(API::getInstance).thenReturn(api);
            extension.hook(mock(ExtensionHook.class));
        }
    }

    private void update(String addOnId, Status status) {
        AddOn addOn = mock(AddOn.class);
        given(addOn.getId()).willReturn(addOnId);
        StatusUpdate statusUpdate =
                mock(StatusUpdate.class, withSettings().strictness(Strictness.LENIENT));
        given(statusUpdate.getAddOn()).willReturn(addOn);
        given(statusUpdate.getStatus()).willReturn(status);

        try (MockedStatic<API> apiStatic = mockStatic(API.class)) {
            apiStatic.when(API::getInstance).thenReturn(api);
            extension.updateStatus(statusUpdate);
        }
    }

    private void unloadExtension() {
        try (MockedStatic<API> apiStatic = mockStatic(API.class)) {
            apiStatic.when(API::getInstance).thenReturn(api);
            extension.unload();
        }
    }

    @Test
    void shouldRegisterApiImplementorWhenAjaxSpiderNotInstalled() {
        // Given / When
        hookExtension();
        // Then
        verify(api).registerApiImplementor(any(AjaxSpiderAPI.class));
    }

    @Test
    void shouldNotRegisterApiImplementorWhenAjaxSpiderAlreadyInstalled() {
        // Given
        given(extensionLoader.getExtension("ExtensionSpiderAjax"))
                .willReturn(mock(Extension.class));
        // When
        hookExtension();
        // Then
        verify(api, never()).registerApiImplementor(any());
    }

    @Test
    void shouldGiveUpApiPrefixWhenAjaxSpiderAddOnBeingInstalled() {
        // Given
        hookExtension();
        // When
        update("spiderAjax", Status.INSTALL);
        // Then
        verify(api).removeApiImplementor(any(AjaxSpiderAPI.class));
    }

    @Test
    void shouldIgnoreStatusUpdatesForOtherAddOns() {
        // Given
        hookExtension();
        // When
        update("otherAddOn", Status.INSTALL);
        // Then
        verify(api, never()).removeApiImplementor(any());
    }

    @Test
    void shouldNotFailGivingUpApiPrefixWhenNothingRegistered() {
        // Given
        given(extensionLoader.getExtension("ExtensionSpiderAjax"))
                .willReturn(mock(Extension.class));
        hookExtension();
        // When
        update("spiderAjax", Status.INSTALL);
        // Then
        verify(api, never()).removeApiImplementor(any());
    }

    @Test
    void shouldTakeBackApiPrefixWhenAjaxSpiderAddOnUninstalled() {
        // Given
        given(extensionLoader.getExtension("ExtensionSpiderAjax"))
                .willReturn(mock(Extension.class));
        hookExtension();
        // When
        update("spiderAjax", Status.UNINSTALLED);
        // Then
        verify(api).registerApiImplementor(any(AjaxSpiderAPI.class));
    }

    @Test
    void shouldTakeBackApiPrefixWhenAjaxSpiderAddOnSoftUninstalled() {
        // Given
        given(extensionLoader.getExtension("ExtensionSpiderAjax"))
                .willReturn(mock(Extension.class));
        hookExtension();
        // When
        update("spiderAjax", Status.SOFT_UNINSTALLED);
        // Then
        verify(api).registerApiImplementor(any(AjaxSpiderAPI.class));
    }

    @Test
    void shouldNotDoubleRegisterApiImplementorWhenAlreadyRegistered() {
        // Given
        hookExtension();
        // When
        update("spiderAjax", Status.UNINSTALLED);
        // Then
        verify(api, times(1)).registerApiImplementor(any());
    }

    @Test
    void shouldRemoveApiImplementorOnUnload() {
        // Given
        hookExtension();
        // When
        unloadExtension();
        // Then
        verify(api).removeApiImplementor(any(AjaxSpiderAPI.class));
    }
}
