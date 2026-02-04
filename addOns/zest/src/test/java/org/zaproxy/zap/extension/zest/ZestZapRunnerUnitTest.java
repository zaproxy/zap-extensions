/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.selenium.ClientAuthenticator;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;
import org.zaproxy.zest.core.v1.ZestClient;
import org.zaproxy.zest.core.v1.ZestClientFailException;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestScript;

/** Unit test for {@link ZestZapRunner}. */
class ZestZapRunnerUnitTest {

    private ExtensionZest extensionZest;
    private ExtensionScript extensionScript;
    private ExtensionNetwork extensionNetwork;
    private ExtensionSelenium extensionSelenium;
    private ExtensionLoader extensionLoader;
    private ZestScriptWrapper scriptWrapper;

    private ZestZapRunner runner;

    @BeforeEach
    void setup() {
        extensionZest = mock();
        extensionScript = mock();
        given(extensionZest.getExtScript()).willReturn(extensionScript);
        extensionNetwork = mock();
        given(extensionNetwork.getMainProxyServerInfo()).willReturn(mock());
        scriptWrapper = mock();

        runner = new ZestZapRunner(extensionZest, extensionNetwork, scriptWrapper);
    }

    @Test
    void shouldRethrowClientZestClientFailExceptions() throws ZestClientFailException {
        // Given
        ZestScript script = mock();
        ZestClient client = mock();
        ZestClientFailException exception = new ZestClientFailException(null);
        given(client.invoke(any())).willThrow(exception);
        // When
        Exception thrown =
                assertThrows(
                        ZestClientFailException.class, () -> runner.handleClient(script, client));
        // Then
        assertThat(thrown, is(sameInstance(exception)));
    }

    @Test
    void shouldThrowClientExceptions() throws ZestClientFailException {
        // Given
        ZestScript script = mock();
        ZestClient client = mock();
        RuntimeException exception = new RuntimeException();
        given(client.invoke(any())).willThrow(exception);
        // When
        ZestClientFailException thrown =
                assertThrows(
                        ZestClientFailException.class, () -> runner.handleClient(script, client));
        // Then
        assertThat(thrown.getElement(), is(sameInstance(client)));
        assertThat(thrown.getCause(), is(sameInstance(exception)));
    }

    @Test
    void shouldCallAuthenticateWithUserFromWrapper() {
        // Given
        extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        extensionSelenium = mock(ExtensionSelenium.class);
        given(extensionLoader.getExtension(ExtensionSelenium.class)).willReturn(extensionSelenium);

        WebDriver webDriver = mock(WebDriver.class);
        WebDriver.Options options = mock(WebDriver.Options.class);
        given(webDriver.manage()).willReturn(options);
        given(options.timeouts()).willReturn(mock(WebDriver.Timeouts.class));
        given(extensionSelenium.getProxiedBrowser(anyString())).willReturn(webDriver);

        User user = mock(User.class);
        given(user.getName()).willReturn("testuser");
        Context context = mock(Context.class);

        TestClientAuthenticatorMethod authMethod = mock(TestClientAuthenticatorMethod.class);
        given(context.getAuthenticationMethod()).willReturn(authMethod);
        given(user.getContext()).willReturn(context);

        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getUser()).willReturn(user);
        ZestZapRunner runnerWithWrapper =
                new ZestZapRunner(extensionZest, extensionNetwork, wrapper);
        ZestClientLaunch clientLaunch = mock(ZestClientLaunch.class);
        given(clientLaunch.getBrowserType()).willReturn("Firefox");
        given(clientLaunch.isHeadless()).willReturn(false);
        given(clientLaunch.getUrl()).willReturn(null);
        given(clientLaunch.getWindowHandle()).willReturn("window1");

        // When
        runnerWithWrapper.launchClient(clientLaunch);

        // Then
        verify(authMethod).authenticate(any(WebDriver.class), eq(user));
    }

    // Test implementation that implements both interfaces to ensure instanceof works
    private abstract static class TestClientAuthenticatorMethod extends AuthenticationMethod
            implements ClientAuthenticator {}
}
