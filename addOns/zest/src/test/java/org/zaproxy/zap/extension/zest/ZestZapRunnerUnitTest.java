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
import static org.hamcrest.Matchers.equalTo;
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
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriver.Timeouts;
import org.openqa.selenium.WebDriverException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.scripts.diagnostics.ScriptDiagnosticSource.RunFailureDiagnostic;
import org.zaproxy.zap.extension.selenium.ClientAuthenticator;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.zest.internal.ZestScriptMerger;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.users.User;
import org.zaproxy.zest.core.v1.ZestClient;
import org.zaproxy.zest.core.v1.ZestClientElementClick;
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
        verify(wrapper, never()).setLastRunFailure(any());
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
        verify(wrapper, times(1)).setLastRunFailure(any());
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
        verify(wrapper, never()).setLastRunFailure(any());
    }

    @Test
    void shouldResetFailureContextWhenWrapperSetViaSetWrapper() {
        ZestScriptWrapper first = mock(ZestScriptWrapper.class);
        ZestScriptWrapper second = mock(ZestScriptWrapper.class);

        ZestZapRunner runner = new ZestZapRunner(extensionZest, extensionNetwork, first);
        clearInvocations(first, second);
        runner.setWrapper(second);

        verify(second).clearRunDiagnostics();
    }

    @Test
    void shouldRefreshStructuredDetailAndContextWhenStatementRecordsAfterPriorLaunchContext()
            throws Exception {
        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getChainProvenance()).willReturn(Optional.empty());
        given(wrapper.getName()).willReturn("zest-script");
        String diagnostics =
                Constant.messages.getString(
                        "zest.runner.failure.standalone", "zest-script", "2", "ZestClientLaunch");

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

        ArgumentCaptor<RunFailureDiagnostic> captor =
                ArgumentCaptor.forClass(RunFailureDiagnostic.class);
        verify(wrapper).setLastRunFailure(captor.capture());
        RunFailureDiagnostic diagnostic = captor.getValue();
        assertThat(diagnostic.detailMessage(), is(equalTo("ZestClientLaunch - wrapped")));
        assertThat(diagnostic.context(), is(equalTo(diagnostics + " - wrapped")));
        assertThat(diagnostic.chainScriptOrder(), is(equalTo(1)));
        assertThat(diagnostic.sourceStatementIndex(), is(equalTo(2)));
        assertThat(diagnostic.elementType(), is(equalTo("ZestClientLaunch")));
    }

    @Test
    void shouldSetClientFailContextFromCauseWhenNoPriorContext() throws Exception {
        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getChainProvenance()).willReturn(Optional.empty());
        given(wrapper.getName()).willReturn("zest-script");

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
        ArgumentCaptor<RunFailureDiagnostic> captor =
                ArgumentCaptor.forClass(RunFailureDiagnostic.class);
        verify(wrapper).setLastRunFailure(captor.capture());
        RunFailureDiagnostic diagnostic = captor.getValue();
        assertThat(diagnostic.detailMessage(), is(equalTo("ZestClientLaunch - " + causeMsg)));
        assertThat(diagnostic.context(), is(equalTo(diagnostics + " - " + causeMsg)));
        assertThat(diagnostic.chainScriptOrder(), is(equalTo(1)));
        assertThat(diagnostic.sourceStatementIndex(), is(equalTo(2)));
        assertThat(diagnostic.elementType(), is(equalTo("ZestClientLaunch")));
    }

    @Test
    void shouldCaptureScreenshotOnClientElementFailure() throws Exception {
        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getChainProvenance()).willReturn(Optional.empty());
        given(wrapper.getName()).willReturn("zest-script");

        ZestZapRunner runnerWithWrapper =
                new ZestZapRunner(extensionZest, extensionNetwork, wrapper);
        clearInvocations(wrapper);
        WebDriver wd = mock(WebDriver.class, withSettings().extraInterfaces(TakesScreenshot.class));
        WebDriver.Options options = mock(WebDriver.Options.class);
        Timeouts timeouts = mock(Timeouts.class);
        given(wd.manage()).willReturn(options);
        given(options.timeouts()).willReturn(timeouts);
        TakesScreenshot screenshot = (TakesScreenshot) wd;
        given(screenshot.getScreenshotAs(eq(OutputType.BASE64))).willReturn("pngb64");
        runnerWithWrapper.addWebDriver("win1", wd);

        ZestClientElementClick click = new ZestClientElementClick("win1", "xpath", "//a");
        ZestClientFailException ex =
                new ZestClientFailException(click, new IllegalStateException("fail"));

        invokeRecordStatementFailureContext(runnerWithWrapper, click, ex);

        ArgumentCaptor<RunFailureDiagnostic> captor =
                ArgumentCaptor.forClass(RunFailureDiagnostic.class);
        verify(wrapper).setLastRunFailure(captor.capture());
        assertThat(captor.getValue().screenshotBase64(), is(equalTo("pngb64")));
        verify(screenshot, times(1)).getScreenshotAs(eq(OutputType.BASE64));

        clearInvocations(wrapper, screenshot);
        ZestClientElementClick clickWithoutHandle = new ZestClientElementClick("", "xpath", "//a");
        invokeRecordStatementFailureContext(
                runnerWithWrapper,
                clickWithoutHandle,
                new ZestClientFailException(clickWithoutHandle, new IllegalStateException("fail")));

        verify(wrapper).setLastRunFailure(captor.capture());
        assertThat(captor.getValue().screenshotBase64(), is(nullValue()));
        verify(screenshot, never()).getScreenshotAs(any());
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

    @Test
    void shouldRecordStdoutOutputWithStandaloneAttribution() {
        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getChainProvenance()).willReturn(Optional.empty());
        given(wrapper.getName()).willReturn("zest-script");
        ZestZapRunner runner = new ZestZapRunner(extensionZest, extensionNetwork, wrapper);

        runner.output("logged in");

        verify(wrapper).appendRunOutput("zest-script", -1, "", "logged in");
    }

    @Test
    void shouldRecordStdoutOutputWithChainAttribution() {
        ZestScriptMerger.ChainProvenance provenance = mock(ZestScriptMerger.ChainProvenance.class);
        ZestScriptMerger.ChainProvenance.StatementOrigin origin =
                new ZestScriptMerger.ChainProvenance.StatementOrigin(1, 5, "ZestActionPrint");
        ZestScript merged = mock(ZestScript.class);
        ZestStatement stmt = mock(ZestStatement.class);
        given(provenance.originForExecutingStatement(merged, stmt)).willReturn(Optional.of(origin));
        given(provenance.segmentScriptName(1)).willReturn(Optional.of("nav-script"));

        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getChainProvenance()).willReturn(Optional.of(provenance));
        given(wrapper.getZestScript()).willReturn(merged);

        ZestZapRunner runner = new ZestZapRunner(extensionZest, extensionNetwork, wrapper);
        setExecutingStatement(runner, stmt);

        runner.output("chain line");

        verify(wrapper).appendRunOutput("nav-script", 5, "ZestActionPrint", "chain line");
    }

    @Test
    void shouldRecordStdoutOutputWithChainAttributionWhenExecutingLookupMisses() {
        ZestScriptMerger.ChainProvenance provenance = mock(ZestScriptMerger.ChainProvenance.class);
        ZestScriptMerger.ChainProvenance.StatementOrigin origin =
                new ZestScriptMerger.ChainProvenance.StatementOrigin(1, 5, "ZestActionPrint");
        ZestScript merged = mock(ZestScript.class);
        ZestStatement stmt = mock(ZestStatement.class);
        given(stmt.getIndex()).willReturn(99);
        given(provenance.originForExecutingStatement(merged, stmt)).willReturn(Optional.empty());
        given(provenance.originForMergedIndex(99)).willReturn(Optional.of(origin));
        given(provenance.segmentScriptName(1)).willReturn(Optional.of("nav-script"));

        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getChainProvenance()).willReturn(Optional.of(provenance));
        given(wrapper.getZestScript()).willReturn(merged);

        ZestZapRunner runner = new ZestZapRunner(extensionZest, extensionNetwork, wrapper);
        setExecutingStatement(runner, stmt);

        runner.output("chain line");

        verify(wrapper).appendRunOutput("nav-script", 5, "ZestActionPrint", "chain line");
    }

    @Test
    void shouldRecordStdoutOutputUsingFirstSegmentWhenChainProvenanceUnknown() {
        ZestScriptMerger.ChainProvenance provenance = mock(ZestScriptMerger.ChainProvenance.class);
        ZestScript merged = mock(ZestScript.class);
        ZestStatement stmt = mock(ZestStatement.class);
        given(stmt.getIndex()).willReturn(99);
        given(stmt.getElementType()).willReturn("ZestActionPrint");
        given(provenance.originForExecutingStatement(merged, stmt)).willReturn(Optional.empty());
        given(provenance.originForMergedIndex(99)).willReturn(Optional.empty());
        given(provenance.segmentScriptName(0)).willReturn(Optional.of("account_check"));

        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getChainProvenance()).willReturn(Optional.of(provenance));
        given(wrapper.getZestScript()).willReturn(merged);

        ZestZapRunner runner = new ZestZapRunner(extensionZest, extensionNetwork, wrapper);
        setExecutingStatement(runner, stmt);

        runner.output("chain line");

        verify(wrapper).appendRunOutput("account_check", -1, "ZestActionPrint", "chain line");
    }

    @Test
    void shouldRecordStdoutOutputUsingWrapperNameWhenSegmentNameMissing() {
        ZestScriptMerger.ChainProvenance provenance = mock(ZestScriptMerger.ChainProvenance.class);
        ZestScriptMerger.ChainProvenance.StatementOrigin origin =
                new ZestScriptMerger.ChainProvenance.StatementOrigin(1, 5, "ZestActionPrint");
        ZestScript merged = mock(ZestScript.class);
        ZestStatement stmt = mock(ZestStatement.class);
        given(provenance.originForExecutingStatement(merged, stmt)).willReturn(Optional.of(origin));
        given(provenance.segmentScriptName(1)).willReturn(Optional.empty());

        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getChainProvenance()).willReturn(Optional.of(provenance));
        given(wrapper.getZestScript()).willReturn(merged);
        given(wrapper.getName()).willReturn("merged-chain");

        ZestZapRunner runner = new ZestZapRunner(extensionZest, extensionNetwork, wrapper);
        setExecutingStatement(runner, stmt);

        runner.output("chain line");

        verify(wrapper).appendRunOutput("merged-chain", 5, "ZestActionPrint", "chain line");
    }

    @Test
    void shouldReuseLastOutputAttributionWhenExecutingStatementCleared() throws Exception {
        ZestScriptMerger.ChainProvenance provenance = mock(ZestScriptMerger.ChainProvenance.class);
        ZestScriptMerger.ChainProvenance.StatementOrigin origin =
                new ZestScriptMerger.ChainProvenance.StatementOrigin(1, 5, "ZestActionPrint");
        ZestScript merged = mock(ZestScript.class);
        ZestStatement stmt = mock(ZestStatement.class);
        given(provenance.originForExecutingStatement(merged, stmt)).willReturn(Optional.of(origin));
        given(provenance.segmentScriptName(1)).willReturn(Optional.of("nav-script"));

        ZestScriptWrapper wrapper = mock(ZestScriptWrapper.class);
        given(wrapper.getChainProvenance()).willReturn(Optional.of(provenance));
        given(wrapper.getZestScript()).willReturn(merged);

        ZestZapRunner runner = new ZestZapRunner(extensionZest, extensionNetwork, wrapper);
        setExecutingStatement(runner, stmt);
        runner.output("during statement");
        setExecutingStatement(runner, null);

        runner.output("between statements");

        verify(wrapper).appendRunOutput("nav-script", 5, "ZestActionPrint", "during statement");
        verify(wrapper).appendRunOutput("nav-script", 5, "ZestActionPrint", "between statements");
    }

    private static void setExecutingStatement(ZestZapRunner runner, ZestStatement stmt) {
        try {
            java.lang.reflect.Field field =
                    ZestZapRunner.class.getDeclaredField("executingStatement");
            field.setAccessible(true);
            field.set(runner, stmt);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    // Test implementation that implements both interfaces to ensure instanceof works
    private abstract static class TestClientAuthenticatorMethod extends AuthenticationMethod
            implements ClientAuthenticator {}
}
