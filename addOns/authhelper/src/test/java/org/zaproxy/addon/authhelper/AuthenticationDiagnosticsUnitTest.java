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
package org.zaproxy.addon.authhelper;

import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.stream.Stream;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Transaction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.AuthDiagnosticsPolicy.Mode;
import org.zaproxy.addon.authhelper.internal.db.Diagnostic;
import org.zaproxy.addon.authhelper.internal.db.TableJdo;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.users.User;

class AuthenticationDiagnosticsUnitTest extends TestUtils {

    private static final String CONTEXT_NAME = "context";

    private AuthDiagnosticsPolicy policy;
    private MockedStatic<TableJdo> tableJdo;
    private PersistenceManager pm;
    private Transaction tx;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionAuthhelper());
        Model model = mock(Model.class);
        Session session = mock(Session.class);
        given(model.getSession()).willReturn(session);
        given(session.getContext(CONTEXT_NAME)).willReturn(mock(Context.class));
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(model);

        policy =
                new AuthDiagnosticsPolicy() {
                    @Override
                    boolean register() {
                        return true;
                    }
                };
        AuthenticationDiagnostics.setRetention(policy);

        pm = mock(PersistenceManager.class);
        tx = mock(Transaction.class);
        lenient().when(pm.currentTransaction()).thenReturn(tx);
        PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
        lenient().when(pmf.getPersistenceManager()).thenReturn(pm);

        tableJdo = mockStatic(TableJdo.class);
        tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
    }

    @AfterEach
    void tearDown() {
        AuthenticationDiagnostics.setRetention(null);
        policy.clearAll();
        tableJdo.close();
    }

    @Test
    void shouldPersistOnClose() {
        // Given / When
        new AuthenticationDiagnostics(true, "method", CONTEXT_NAME, "user").close();
        // Then
        verify(pm).makePersistent(any(Diagnostic.class));
        verify(tx).commit();
    }

    @Test
    void shouldDeferToPolicyInsteadOfPersistingWhenPolicyActive() {
        // Given
        policy.configure(CONTEXT_NAME, Mode.AUTH_ON_FAILURE, 5);
        User user = mock(User.class);
        Context userContext = mock(Context.class);
        given(userContext.getName()).willReturn(CONTEXT_NAME);
        given(user.getContext()).willReturn(userContext);
        given(user.getName()).willReturn("user");

        // When: constructed disabled, but policy is active for this context.
        new AuthenticationDiagnostics(false, "method", CONTEXT_NAME, "user").close();
        // Then: close() deferred to the policy rather than persisting directly.
        verify(pm, never()).makePersistent(any());

        // And: the policy can still commit the deferred diagnostic on failure.
        policy.onAuthenticationRequestFailure(user, mock(HttpMessage.class));
        verify(pm).makePersistent(any(Diagnostic.class));
    }

    @Test
    void shouldNotPersistWhenDisabled() {
        // Given
        AuthenticationDiagnostics diags =
                new AuthenticationDiagnostics(false, "method", CONTEXT_NAME, "user");
        // When
        diags.close();
        // Then
        verify(pm, never()).makePersistent(any());
    }

    private static WebDriver webDriver() {
        return mock(
                WebDriver.class,
                withSettings()
                        .defaultAnswer(Answers.RETURNS_DEEP_STUBS)
                        .extraInterfaces(TakesScreenshot.class, JavascriptExecutor.class));
    }

    static Stream<Arguments> stepRecording() {
        return Stream.of(
                arguments(false, Mode.AUTH_ON_FAILURE, false, false, false),
                arguments(false, Mode.AUTH_ON_FAILURE, true, true, false),
                arguments(false, Mode.AUTH_FAILURE_ROLLING, false, true, true),
                arguments(true, Mode.AUTH_ON_FAILURE, false, true, true));
    }

    @ParameterizedTest
    @MethodSource("stepRecording")
    void shouldRecordStepDataAccordingToModeAndStep(
            boolean enabled,
            Mode mode,
            boolean errorStep,
            boolean screenshot,
            boolean elementsAndStorage) {
        // Given
        policy.configure(CONTEXT_NAME, mode, 2);
        WebDriver wd = webDriver();
        try (AuthenticationDiagnostics diags =
                new AuthenticationDiagnostics(enabled, "method", CONTEXT_NAME, "user")) {
            // When
            if (errorStep) {
                diags.recordErrorStep(wd);
            } else {
                diags.recordStep(wd, "step");
            }
        }
        // Then
        verify((TakesScreenshot) wd, screenshot ? atLeastOnce() : never())
                .getScreenshotAs(OutputType.BASE64);
        verify(wd, elementsAndStorage ? atLeastOnce() : never()).findElements(any(By.class));
        verify((JavascriptExecutor) wd, elementsAndStorage ? atLeastOnce() : never())
                .executeScript(anyString());
    }
}
