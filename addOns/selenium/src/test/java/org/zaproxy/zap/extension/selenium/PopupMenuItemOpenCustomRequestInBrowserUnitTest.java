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
package org.zaproxy.zap.extension.selenium;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.RETURNS_MOCKS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.TestUtils;

class PopupMenuItemOpenCustomRequestInBrowserUnitTest extends TestUtils {
    private ExtensionSelenium extensionSelenium;
    private ProvidedBrowser providedBrowser;
    private PopupMenuItemOpenCustomRequestInBrowser popupMenuItemOpenCustomRequestInBrowser;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
        extensionSelenium =
                mock(
                        ExtensionSelenium.class,
                        withSettings().defaultAnswer(RETURNS_MOCKS).lenient());
        providedBrowser =
                mock(ProvidedBrowser.class, withSettings().defaultAnswer(RETURNS_MOCKS).lenient());
    }

    @Test
    void shouldNotThrowExceptionsForValidHttpMessage() throws InterruptedException {
        // Given
        HttpMessage httpMessage =
                mock(HttpMessage.class, withSettings().defaultAnswer(RETURNS_MOCKS).lenient());
        popupMenuItemOpenCustomRequestInBrowser =
                new PopupMenuItemOpenCustomRequestInBrowser(
                        "chrome", extensionSelenium, providedBrowser);
        // When
        popupMenuItemOpenCustomRequestInBrowser.openInBrowser(httpMessage);

        // Then
        ArgumentCaptor<String> argumentCaptorForBrowserId = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> argumentCaptorForUrl = ArgumentCaptor.forClass(String.class);

        verify(extensionSelenium)
                .getProxiedBrowser(
                        argumentCaptorForBrowserId.capture(), argumentCaptorForUrl.capture());

        assertEquals(argumentCaptorForBrowserId.getValue(), providedBrowser.getId());
        assertThat(argumentCaptorForUrl.getValue(), containsString("zapCallBackUrl"));
        assertThat(argumentCaptorForUrl.getValue(), containsString("?hist="));
    }
}
