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
package org.zaproxy.addon.client;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;

/** Unit test for {@link RedirectScript}. */
class RedirectScriptUnitTest {

    private static final String DISABLE_CLIENT_SCRIPT =
            "localStorage.setItem('localzapenable',false)";

    private TestWebDriver wd;
    private SeleniumScriptUtils ssutils;
    private ClientIntegrationAPI api;
    private RedirectScript script;

    @BeforeEach
    void setUp() {
        ssutils = mock(SeleniumScriptUtils.class);
        wd = mock(TestWebDriver.class);
        given(ssutils.getWebDriver()).willReturn(wd);
        api = mock(ClientIntegrationAPI.class);
        given(api.getCallbackUrl()).willReturn("callback-url");

        script = new RedirectScript(api);
    }

    @ParameterizedTest
    @ValueSource(ints = {HttpSender.PROXY_INITIATOR, HttpSender.AJAX_SPIDER_INITIATOR})
    void shouldNotDisableClientForCommonInitiators(int initiator) {
        // Given
        given(ssutils.getRequester()).willReturn(initiator);
        // When
        script.browserLaunched(ssutils);
        // Then
        verify(wd, times(0)).executeScript(DISABLE_CLIENT_SCRIPT);
    }

    @Test
    void shouldDisableClientForZestRecorder() {
        // Given
        given(ssutils.getRequester()).willReturn(RedirectScript.ZEST_CLIENT_RECORDER_INITIATOR);
        // When
        script.browserLaunched(ssutils);
        // Then
        verify(wd).executeScript(DISABLE_CLIENT_SCRIPT);
    }

    private interface TestWebDriver extends WebDriver, JavascriptExecutor {}
}
