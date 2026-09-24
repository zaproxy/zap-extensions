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
package org.zaproxy.zap.extension.spiderAjax;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.selenium.DriverConfiguration;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link SpiderThread}. */
class SpiderThreadUnitTest extends TestUtils {

    @Nested
    class WebDriverProcessUnitTest {

        private ExtensionLoader extensionLoader;
        private ExtensionSelenium extSelenium;
        private ExtensionNetwork network;
        private Server server;
        private HttpMessageHandler listener;
        private WebDriver wd;

        @BeforeEach
        void setUp() throws Exception {
            setUpZap();
            mockMessages(new ExtensionAjax());

            extensionLoader = mock(withSettings().strictness(Strictness.LENIENT));
            extSelenium = mock(withSettings().strictness(Strictness.LENIENT));
            given(extensionLoader.getExtension(ExtensionSelenium.class)).willReturn(extSelenium);
            Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

            network = mock(withSettings().strictness(Strictness.LENIENT));
            server = mock(withSettings().strictness(Strictness.LENIENT));
            given(network.createHttpServer(any(HttpServerConfig.class))).willReturn(server);
            given(server.start(anyInt())).willReturn(8080);

            listener = mock();

            wd = mock(withSettings().strictness(Strictness.LENIENT));
            given(extSelenium.getWebDriver(any(String.class), any(DriverConfiguration.class)))
                    .willReturn(wd);
        }

        @Test
        void shouldSetSynchronousScriptExecutionInDriverConfiguration() throws Exception {
            // Given
            ArgumentCaptor<DriverConfiguration> confCaptor = ArgumentCaptor.captor();

            // When
            new SpiderThread.WebDriverProcess(network, listener, "firefox", true);

            // Then
            verify(extSelenium).getWebDriver(any(), confCaptor.capture());
            assertThat(confCaptor.getValue().isSyncScriptExecution(), is(true));
        }
    }
}
