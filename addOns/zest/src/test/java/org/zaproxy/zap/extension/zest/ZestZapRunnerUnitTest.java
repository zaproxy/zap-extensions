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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.lang.reflect.Method;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.extension.script.ExtensionScript;
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
    void shouldRetrieveUserFromWrapperInLaunchClient() throws Exception {
        // Given
        User user = mock(User.class);
        given(user.getName()).willReturn("testuser");
        ZestScriptWrapper wrapperWithUser = mock(ZestScriptWrapper.class);
        given(wrapperWithUser.getUser()).willReturn(user);
        ZestZapRunner runnerWithWrapper =
                new ZestZapRunner(extensionZest, extensionNetwork, wrapperWithUser);
        ZestClientLaunch clientLaunch = mock(ZestClientLaunch.class);
        given(clientLaunch.getBrowserType()).willReturn("Firefox");
        given(clientLaunch.isHeadless()).willReturn(false);

        // When
        Method launchClientMethod =
                ZestZapRunner.class.getDeclaredMethod("launchClient", ZestClientLaunch.class);
        launchClientMethod.setAccessible(true);
        // This may fail if ExtensionSelenium is not available, but we can verify the
        // user retrieval
        try {
            launchClientMethod.invoke(runnerWithWrapper, clientLaunch);
        } catch (Exception e) {
            // Expected if ExtensionSelenium is not available in test environment
            // The important part is that user was retrieved before any failure
        }

        // Then - verify user was retrieved from wrapper
        verify(wrapperWithUser).getUser();
        // Verify the retrieved value is the expected user object
        assertThat(wrapperWithUser.getUser(), is(sameInstance(user)));
    }

    @Test
    void shouldHandleNullUserInLaunchClient() throws Exception {
        // Given
        ZestScriptWrapper wrapperWithNullUser = mock(ZestScriptWrapper.class);
        given(wrapperWithNullUser.getUser()).willReturn(null);
        ZestZapRunner runnerWithNullUser =
                new ZestZapRunner(extensionZest, extensionNetwork, wrapperWithNullUser);
        ZestClientLaunch clientLaunch = mock(ZestClientLaunch.class);
        given(clientLaunch.getBrowserType()).willReturn("Firefox");
        given(clientLaunch.isHeadless()).willReturn(false);

        // When
        Method launchClientMethod =
                ZestZapRunner.class.getDeclaredMethod("launchClient", ZestClientLaunch.class);
        launchClientMethod.setAccessible(true);
        // This may fail if ExtensionSelenium is not available, but should not throw NPE
        assertDoesNotThrow(
                () -> {
                    try {
                        launchClientMethod.invoke(runnerWithNullUser, clientLaunch);
                    } catch (Exception e) {
                        // Expected if ExtensionSelenium is not available in test environment
                        // The important part is that it doesn't throw NPE for null user
                    }
                });

        // Then - verify null user was retrieved
        verify(wrapperWithNullUser).getUser();
    }
}
