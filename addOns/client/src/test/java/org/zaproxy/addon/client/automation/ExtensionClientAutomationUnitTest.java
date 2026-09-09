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
package org.zaproxy.addon.client.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate.Status;
import org.zaproxy.zap.testutils.TestUtils;

class ExtensionClientAutomationUnitTest extends TestUtils {

    private ExtensionLoader extensionLoader;
    private ExtensionAutomation extAuto;
    private ExtensionClientAutomation extension;

    @BeforeEach
    void setUp() {
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extAuto = mock(ExtensionAutomation.class);
        given(extensionLoader.getExtension(ExtensionAutomation.class)).willReturn(extAuto);
        given(extensionLoader.getExtension(ExtensionClientIntegration.class))
                .willReturn(mock(ExtensionClientIntegration.class));
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);

        mockMessages(new ExtensionClientIntegration());

        extension = new ExtensionClientAutomation();
    }

    private void hookExtension() {
        extension.hook(mock(ExtensionHook.class));
    }

    private void update(String addOnId, Status status) {
        AddOn addOn = mock(AddOn.class);
        given(addOn.getId()).willReturn(addOnId);
        StatusUpdate statusUpdate =
                mock(StatusUpdate.class, withSettings().strictness(Strictness.LENIENT));
        given(statusUpdate.getAddOn()).willReturn(addOn);
        given(statusUpdate.getStatus()).willReturn(status);

        extension.updateStatus(statusUpdate);
    }

    @Test
    void shouldRegisterClientSpiderAndAjaxSpiderJobsWhenAjaxSpiderNotInstalled() {
        // Given / When
        hookExtension();
        // Then
        ArgumentCaptor<AutomationJob> captor = ArgumentCaptor.forClass(AutomationJob.class);
        verify(extAuto, times(2)).registerAutomationJob(captor.capture());
        List<String> types = captor.getAllValues().stream().map(AutomationJob::getType).toList();
        assertThat(types, containsInAnyOrder("spiderClient", "spiderAjax"));
    }

    @Test
    void shouldOnlyRegisterClientSpiderJobWhenAjaxSpiderAlreadyInstalled() {
        // Given
        given(extensionLoader.getExtension("ExtensionSpiderAjax"))
                .willReturn(mock(Extension.class));
        // When
        hookExtension();
        // Then
        ArgumentCaptor<AutomationJob> captor = ArgumentCaptor.forClass(AutomationJob.class);
        verify(extAuto, times(1)).registerAutomationJob(captor.capture());
        assertThat(captor.getValue().getType(), is(equalTo("spiderClient")));
    }

    @Test
    void shouldGiveUpAjaxSpiderJobTypeWhenAjaxSpiderAddOnBeingInstalled() {
        // Given
        hookExtension();
        // When
        update("spiderAjax", Status.INSTALL);
        // Then
        ArgumentCaptor<AutomationJob> captor = ArgumentCaptor.forClass(AutomationJob.class);
        verify(extAuto, times(1)).unregisterAutomationJob(captor.capture());
        assertThat(captor.getValue().getType(), is(equalTo("spiderAjax")));
    }

    @Test
    void shouldIgnoreStatusUpdatesForOtherAddOns() {
        // Given
        hookExtension();
        // When
        update("otherAddOn", Status.INSTALL);
        // Then
        verify(extAuto, never()).unregisterAutomationJob(any());
    }

    @Test
    void shouldNotFailGivingUpAjaxSpiderJobWhenNothingRegistered() {
        // Given
        given(extensionLoader.getExtension("ExtensionSpiderAjax"))
                .willReturn(mock(Extension.class));
        hookExtension();
        // When
        update("spiderAjax", Status.INSTALL);
        // Then
        verify(extAuto, never()).unregisterAutomationJob(any());
    }

    @Test
    void shouldTakeBackAjaxSpiderJobTypeWhenAjaxSpiderAddOnUninstalled() {
        // Given
        given(extensionLoader.getExtension("ExtensionSpiderAjax"))
                .willReturn(mock(Extension.class));
        hookExtension();
        // When
        update("spiderAjax", Status.UNINSTALLED);
        // Then
        ArgumentCaptor<AutomationJob> captor = ArgumentCaptor.forClass(AutomationJob.class);
        verify(extAuto, times(2)).registerAutomationJob(captor.capture());
        List<String> types = captor.getAllValues().stream().map(AutomationJob::getType).toList();
        assertThat(types, containsInAnyOrder("spiderClient", "spiderAjax"));
    }

    @Test
    void shouldTakeBackAjaxSpiderJobTypeWhenAjaxSpiderAddOnSoftUninstalled() {
        // Given
        given(extensionLoader.getExtension("ExtensionSpiderAjax"))
                .willReturn(mock(Extension.class));
        hookExtension();
        // When
        update("spiderAjax", Status.SOFT_UNINSTALLED);
        // Then
        ArgumentCaptor<AutomationJob> captor = ArgumentCaptor.forClass(AutomationJob.class);
        verify(extAuto, times(2)).registerAutomationJob(captor.capture());
        List<String> types = captor.getAllValues().stream().map(AutomationJob::getType).toList();
        assertThat(types, containsInAnyOrder("spiderClient", "spiderAjax"));
    }

    @Test
    void shouldNotDoubleRegisterAjaxSpiderJobWhenAlreadyRegistered() {
        // Given
        hookExtension();
        // When
        update("spiderAjax", Status.UNINSTALLED);
        update("spiderAjax", Status.UNINSTALLED);
        // Then
        ArgumentCaptor<AutomationJob> captor = ArgumentCaptor.forClass(AutomationJob.class);
        verify(extAuto, times(2)).registerAutomationJob(captor.capture());
        List<String> types = captor.getAllValues().stream().map(AutomationJob::getType).toList();
        assertThat(types, containsInAnyOrder("spiderClient", "spiderAjax"));
    }

    @Test
    void shouldUnregisterAllJobsOnUnload() {
        // Given
        hookExtension();
        // When
        extension.unload();
        // Then
        ArgumentCaptor<AutomationJob> captor = ArgumentCaptor.forClass(AutomationJob.class);
        verify(extAuto, times(2)).unregisterAutomationJob(captor.capture());
        List<String> types = captor.getAllValues().stream().map(AutomationJob::getType).toList();
        assertThat(types, containsInAnyOrder("spiderClient", "spiderAjax"));
    }
}
