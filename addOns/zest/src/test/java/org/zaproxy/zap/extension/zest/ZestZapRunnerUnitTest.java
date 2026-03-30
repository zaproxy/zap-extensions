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
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.lang.reflect.Method;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.selenium.ClientAuthenticator;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.zest.internal.ZestScriptMerger;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.users.User;
import org.zaproxy.zest.core.v1.ZestClient;
import org.zaproxy.zest.core.v1.ZestClientFailException;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

/** Unit test for {@link ZestZapRunner}. */
class ZestZapRunnerUnitTest extends TestUtils {

    private ExtensionZest extensionZest;
    private ExtensionScript extensionScript;
    private ExtensionNetwork extensionNetwork;
    private ExtensionSelenium extensionSelenium;
    private ExtensionLoader extensionLoader;
    private ZestScriptWrapper scriptWrapper;

    private ZestZapRunner runner;

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionZest());
    }

    @BeforeEach
    void setup() {
        extensionZest = mock(ExtensionZest.class, withSettings().strictness(Strictness.LENIENT));
        extensionScript =
                mock(ExtensionScript.class, withSettings().strictness(Strictness.LENIENT));
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
    void shouldCallAuthenticateWithUserFromWrapper() throws ZestClientFailException {
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

        User user = mock(User.class, withSettings().strictness(Strictness.LENIENT));
        given(user.getName()).willReturn("testuser");
        Context context = mock(Context.class);

        TestClientAuthenticatorMethod authMethod = mock(TestClientAuthenticatorMethod.class);
        given(authMethod.authenticate(any(WebDriver.class), eq(user))).willReturn(true);
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

    @Test
    void shouldReturnNullWhenClientAuthenticationFailsForStandaloneScript()
            throws ZestClientFailException {
        extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        extensionSelenium = mock(ExtensionSelenium.class);
        given(extensionLoader.getExtension(ExtensionSelenium.class)).willReturn(extensionSelenium);

        WebDriver webDriver = mock(WebDriver.class);
        given(extensionSelenium.getProxiedBrowser(anyString())).willReturn(webDriver);

        User user = mock(User.class);
        given(user.getName()).willReturn("testuser");
        Context context = mock(Context.class);

        TestClientAuthenticatorMethod authMethod = mock(TestClientAuthenticatorMethod.class);
        given(authMethod.authenticate(any(WebDriver.class), eq(user))).willReturn(false);
        given(context.getAuthenticationMethod()).willReturn(authMethod);
        given(user.getContext()).willReturn(context);

        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getUser()).willReturn(user);
        given(wrapper.getChainProvenance()).willReturn(Optional.empty());
        ZestZapRunner runnerWithWrapper =
                new ZestZapRunner(extensionZest, extensionNetwork, wrapper);
        ZestClientLaunch clientLaunch = mock(ZestClientLaunch.class);
        given(clientLaunch.getBrowserType()).willReturn("Firefox");
        given(clientLaunch.isHeadless()).willReturn(false);
        given(clientLaunch.getUrl()).willReturn(null);

        assertThat(runnerWithWrapper.launchClient(clientLaunch), is(nullValue()));
        verify(wrapper, times(1)).setZestFailureContext("");
        verify(authMethod).authenticate(any(WebDriver.class), eq(user));
    }

    @Test
    void shouldThrowWhenClientAuthenticationFailsForChain() {
        extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        extensionSelenium = mock(ExtensionSelenium.class);
        given(extensionLoader.getExtension(ExtensionSelenium.class)).willReturn(extensionSelenium);

        WebDriver webDriver = mock(WebDriver.class);
        given(extensionSelenium.getProxiedBrowser(anyString())).willReturn(webDriver);

        User user = mock(User.class);
        given(user.getName()).willReturn("testuser");
        Context context = mock(Context.class);
        given(context.getName()).willReturn("ctx1");

        TestClientAuthenticatorMethod authMethod = mock(TestClientAuthenticatorMethod.class);
        given(authMethod.authenticate(any(WebDriver.class), eq(user))).willReturn(false);
        given(context.getAuthenticationMethod()).willReturn(authMethod);
        given(user.getContext()).willReturn(context);

        ZestScriptMerger.ChainProvenance provenance = mock(ZestScriptMerger.ChainProvenance.class);
        given(provenance.describe(eq(2))).willReturn("diag line");
        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getUser()).willReturn(user);
        given(wrapper.getChainProvenance()).willReturn(Optional.of(provenance));
        ZestZapRunner runnerWithWrapper =
                new ZestZapRunner(extensionZest, extensionNetwork, wrapper);
        ZestClientLaunch clientLaunch = mock(ZestClientLaunch.class);
        given(clientLaunch.getBrowserType()).willReturn("Firefox");
        given(clientLaunch.isHeadless()).willReturn(false);
        given(clientLaunch.getUrl()).willReturn(null);
        given(clientLaunch.getIndex()).willReturn(2);

        assertThrows(
                ZestClientFailException.class, () -> runnerWithWrapper.launchClient(clientLaunch));
        verify(wrapper, times(2)).setZestFailureContext(anyString());
    }

    @Test
    void shouldResetFailureContextWhenRunnerConstructedAndLaunchSucceeds()
            throws ZestClientFailException {
        extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        extensionSelenium = mock(ExtensionSelenium.class);
        given(extensionLoader.getExtension(ExtensionSelenium.class)).willReturn(extensionSelenium);

        WebDriver webDriver = mock(WebDriver.class);
        WebDriver.Options options = mock(WebDriver.Options.class);
        given(webDriver.manage()).willReturn(options);
        given(options.timeouts()).willReturn(mock(WebDriver.Timeouts.class));
        given(extensionSelenium.getProxiedBrowser(anyString())).willReturn(webDriver);

        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getUser()).willReturn(null);

        ZestZapRunner runnerWithWrapper =
                new ZestZapRunner(extensionZest, extensionNetwork, wrapper);
        ZestClientLaunch clientLaunch = mock(ZestClientLaunch.class);
        given(clientLaunch.getBrowserType()).willReturn("Firefox");
        given(clientLaunch.isHeadless()).willReturn(false);
        given(clientLaunch.getUrl()).willReturn(null);
        given(clientLaunch.getWindowHandle()).willReturn("win1");

        assertThat(runnerWithWrapper.launchClient(clientLaunch), is("win1"));
        verify(wrapper, times(1)).setZestFailureContext("");
    }

    @Test
    void shouldResetFailureContextWhenWrapperSetViaSetWrapper() {
        ZestScriptWrapper first = mock(ZestScriptWrapper.class);
        ZestScriptWrapper second = mock(ZestScriptWrapper.class);

        ZestZapRunner runner = new ZestZapRunner(extensionZest, extensionNetwork, first);
        clearInvocations(first, second);
        runner.setWrapper(second);

        verify(second).setZestFailureContext("");
    }

    @Test
    void shouldPreserveClientLaunchFailureContextWhenStatementRecordsClientFailException()
            throws Exception {
        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getChainProvenance()).willReturn(Optional.empty());
        given(wrapper.getName()).willReturn("zest-script");
        String diagnostics =
                Constant.messages.getString(
                        "zest.runner.failure.standalone", "zest-script", "2", "ZestClientLaunch");
        String headline = "headline from launch path";
        given(wrapper.getZestFailureContext()).willReturn(diagnostics + " - " + headline);

        ZestZapRunner runnerWithWrapper =
                new ZestZapRunner(extensionZest, extensionNetwork, wrapper);
        clearInvocations(wrapper);
        ZestStatement stmt = mock(ZestStatement.class);
        given(stmt.getIndex()).willReturn(2);
        given(stmt.getElementType()).willReturn("ZestClientLaunch");
        ZestClientFailException ex =
                new ZestClientFailException(
                        mock(ZestClientLaunch.class), new IllegalStateException("wrapped"));

        invokeRecordStatementFailureContext(runnerWithWrapper, stmt, ex);

        verify(wrapper, never()).setZestFailureContext(anyString());
    }

    @Test
    void shouldSetClientFailContextFromCauseWhenNoPriorContext() throws Exception {
        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getChainProvenance()).willReturn(Optional.empty());
        given(wrapper.getName()).willReturn("zest-script");
        given(wrapper.getZestFailureContext()).willReturn("");

        ZestZapRunner runnerWithWrapper =
                new ZestZapRunner(extensionZest, extensionNetwork, wrapper);
        clearInvocations(wrapper);
        ZestStatement stmt = mock(ZestStatement.class);
        given(stmt.getIndex()).willReturn(2);
        given(stmt.getElementType()).willReturn("ZestClientLaunch");
        String causeMsg = "browser failed detail";
        ZestClientFailException ex =
                new ZestClientFailException(
                        mock(ZestClientLaunch.class), new IllegalStateException(causeMsg));

        invokeRecordStatementFailureContext(runnerWithWrapper, stmt, ex);

        String diagnostics =
                Constant.messages.getString(
                        "zest.runner.failure.standalone", "zest-script", "2", "ZestClientLaunch");
        verify(wrapper).setZestFailureContext(diagnostics + " - " + causeMsg);
    }

    @Test
    void shouldUseWebDriverExceptionRawMessageInStatementFailureDetail() throws Exception {
        WebDriverException cause = new WebDriverException("selenium raw headline");
        ZestClientFailException ex =
                new ZestClientFailException(mock(ZestClientLaunch.class), cause);

        assertThat(invokeFormatStatementFailureDetail(ex), is(cause.getRawMessage()));
    }

    @Test
    void shouldLeaveNonSeleniumCauseMessageUnchangedInStatementFailureDetail() throws Exception {
        ZestClientFailException ex =
                new ZestClientFailException(
                        mock(ZestClientLaunch.class), new IllegalStateException("plain cause"));

        assertThat(invokeFormatStatementFailureDetail(ex), is("plain cause"));
    }

    private static String invokeFormatStatementFailureDetail(Throwable t) throws Exception {
        Method m =
                ZestZapRunner.class.getDeclaredMethod(
                        "formatStatementFailureDetail", Throwable.class);
        m.setAccessible(true);
        return (String) m.invoke(null, t);
    }

    private static void invokeRecordStatementFailureContext(
            ZestZapRunner runner, ZestStatement stmt, Throwable t) throws Exception {
        Method m =
                ZestZapRunner.class.getDeclaredMethod(
                        "recordStatementFailureContext", ZestStatement.class, Throwable.class);
        m.setAccessible(true);
        m.invoke(runner, stmt, t);
    }

    // Test implementation that implements both interfaces to ensure instanceof works
    private abstract static class TestClientAuthenticatorMethod extends AuthenticationMethod
            implements ClientAuthenticator {}
}
