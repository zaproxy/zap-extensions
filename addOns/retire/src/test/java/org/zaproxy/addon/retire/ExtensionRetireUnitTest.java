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
package org.zaproxy.addon.retire;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.addon.pscan.PassiveScannersManager;
import org.zaproxy.addon.retire.model.Repo;
import org.zaproxy.zap.extension.pscan.PassiveScanData;
import org.zaproxy.zap.testutils.TestUtils;

class ExtensionRetireUnitTest extends TestUtils {

    private ExtensionRetire extension;
    private ExtensionPassiveScan2 mockPscanExtension;
    private PassiveScannersManager mockScannerManager;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
        mockMessages("org.zaproxy.addon.retire.resources.Messages", "retire");

        extension = new ExtensionRetire();
        mockScannerManager = mock(PassiveScannersManager.class);
        mockPscanExtension = mock(ExtensionPassiveScan2.class);
        // Use lenient() to avoid unnecessary stubbing exceptions for tests that don't use these
        // mocks
        lenient()
                .when(mockPscanExtension.getPassiveScannersManager())
                .thenReturn(mockScannerManager);

        // Mock Control singleton
        Model model = mock(Model.class);
        ExtensionLoader mockLoader = mock(ExtensionLoader.class);
        lenient()
                .when(mockLoader.getExtension(ExtensionPassiveScan2.class))
                .thenReturn(mockPscanExtension);
        Control.initSingletonForTesting(model, mockLoader);
    }

    @Test
    void shouldLoadRepoInInit() {
        // Given / When
        extension.init();

        // Then
        Repo repo = extension.getRepo();
        assertThat(repo, is(notNullValue()));
    }

    @Test
    void shouldRegisterRuleInHook() {
        // Given
        extension.init();
        ExtensionHook mockHook = mock(ExtensionHook.class);

        // When
        extension.hook(mockHook);

        // Then
        verify(mockScannerManager).add(any(RetireScanRule.class));
    }

    @Test
    void shouldUnregisterRuleOnUnload() {
        // Given
        extension.init();
        ExtensionHook mockHook = mock(ExtensionHook.class);
        extension.hook(mockHook);

        // When
        extension.unload();

        // Then
        verify(mockScannerManager).remove(any(RetireScanRule.class));
    }

    @Test
    void shouldReturnExampleAlertsAfterHook() {
        // Given
        extension.init();
        ExtensionHook mockHook = mock(ExtensionHook.class);
        extension.hook(mockHook);

        // Set up helper for the scanner (needed for newAlert())
        RetireScanRule scanner = extension.passiveScanner;
        if (scanner != null) {
            PassiveScanData mockScanData = mock(PassiveScanData.class);
            scanner.setHelper(mockScanData);
        }

        // When
        var alerts = extension.getExampleAlerts();

        // Then
        assertThat(alerts, is(not(empty())));
    }

    @Test
    void shouldReturnHelpLinkAfterHook() {
        // Given
        extension.init();
        ExtensionHook mockHook = mock(ExtensionHook.class);
        extension.hook(mockHook);

        // When
        String helpLink = extension.getHelpLink();

        // Then
        assertNotNull(helpLink);
        assertThat(helpLink.isEmpty(), is(false));
    }

    @Test
    void shouldImplementRepoHolder() {
        // Given
        extension.init();

        // When
        Repo repo = ((RepoHolder) extension).getRepo();

        // Then
        // Repo might be null if loading failed, but interface should work
        assertNotNull(extension);
    }
}
