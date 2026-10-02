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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Transaction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.AuthDiagnosticsPolicy.Mode;
import org.zaproxy.addon.authhelper.internal.db.Diagnostic;
import org.zaproxy.addon.authhelper.internal.db.TableJdo;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.users.User;

class AuthDiagnosticsPolicyUnitTest extends TestUtils {

    private static final String CONTEXT_NAME = "context";

    private AuthDiagnosticsPolicy policy;
    private MockedStatic<TableJdo> tableJdo;
    private PersistenceManager pm;

    @BeforeEach
    void setUp() {
        policy = AuthDiagnosticsPolicy.getInstance();

        pm = mock(PersistenceManager.class);
        Transaction tx = mock(Transaction.class);
        lenient().when(pm.currentTransaction()).thenReturn(tx);
        lenient().when(pm.getObjectById(Diagnostic.class, 0)).thenReturn(new Diagnostic());
        PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
        lenient().when(pmf.getPersistenceManager()).thenReturn(pm);

        tableJdo = mockStatic(TableJdo.class);
        tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
    }

    @AfterEach
    void tearDown() {
        policy.clearAll();
        tableJdo.close();
    }

    private static User userNamed(String name) {
        User user = mock(User.class);
        Context context = mock(Context.class);
        given(context.getName()).willReturn(CONTEXT_NAME);
        given(user.getContext()).willReturn(context);
        given(user.getName()).willReturn(name);
        return user;
    }

    @Test
    void shouldNotBeActiveBeforeConfigure() {
        assertThat(policy.isActive(CONTEXT_NAME), is(false));
    }

    @Test
    void shouldBeActiveOnlyForConfiguredContext() {
        // Given / When
        policy.configure(CONTEXT_NAME, Mode.AUTH_ON_FAILURE, 5);
        // Then
        assertThat(policy.isActive(CONTEXT_NAME), is(true));
        assertThat(policy.isActive("other"), is(false));
    }

    @Test
    void shouldSupportMultipleContextsConcurrently() {
        // Given / When
        policy.configure(CONTEXT_NAME, Mode.AUTH_ON_FAILURE, 5);
        policy.configure("other", Mode.AUTH_FAILURE_ROLLING, 3);
        // Then
        assertThat(policy.isActive(CONTEXT_NAME), is(true));
        assertThat(policy.isActive("other"), is(true));

        // When: clearing one context
        policy.clear(CONTEXT_NAME);
        // Then: the other is unaffected
        assertThat(policy.isActive(CONTEXT_NAME), is(false));
        assertThat(policy.isActive("other"), is(true));

        policy.clear("other");
    }

    @Test
    void shouldNotBeActiveAfterClear() {
        // Given
        policy.configure(CONTEXT_NAME, Mode.AUTH_ON_FAILURE, 5);
        // When
        policy.clear(CONTEXT_NAME);
        // Then
        assertThat(policy.isActive(CONTEXT_NAME), is(false));
    }

    @Test
    void shouldNotPersistOnSuccess() {
        // Given
        policy.configure(CONTEXT_NAME, Mode.AUTH_ON_FAILURE, 5);
        Diagnostic diagnostic = new Diagnostic("method", CONTEXT_NAME, "alice");
        policy.defer(diagnostic);
        User user = userNamed("alice");
        // When
        policy.onAuthenticationRequestSuccess(user, mock(HttpMessage.class));
        // Then
        verify(pm, never()).makePersistent(any());
    }

    @Test
    void shouldPersistOnFailure() {
        // Given
        policy.configure(CONTEXT_NAME, Mode.AUTH_ON_FAILURE, 5);
        Diagnostic diagnostic = new Diagnostic("method", CONTEXT_NAME, "alice");
        policy.defer(diagnostic);
        User user = userNamed("alice");
        // When
        policy.onAuthenticationRequestFailure(user, mock(HttpMessage.class));
        // Then
        verify(pm, times(1)).makePersistent(same(diagnostic));
    }

    @Test
    void shouldReplacePreviousFailureOnAuthOnFailure() {
        // Given
        policy.configure(CONTEXT_NAME, Mode.AUTH_ON_FAILURE, 5);
        User user = userNamed("alice");

        Diagnostic first = new Diagnostic("method", CONTEXT_NAME, "alice");
        policy.defer(first);
        policy.onAuthenticationRequestFailure(user, mock(HttpMessage.class));

        Diagnostic second = new Diagnostic("method", CONTEXT_NAME, "alice");
        policy.defer(second);
        // When
        policy.onAuthenticationRequestFailure(user, mock(HttpMessage.class));
        // Then
        verify(pm, times(1)).deletePersistent(any());
        verify(pm, times(1)).makePersistent(same(first));
        verify(pm, times(1)).makePersistent(same(second));
    }

    @Test
    void shouldCapRollingFailuresAtCount() {
        // Given
        policy.configure(CONTEXT_NAME, Mode.AUTH_FAILURE_ROLLING, 2);
        User user = userNamed("alice");

        // When
        for (int i = 0; i < 3; i++) {
            Diagnostic diagnostic = new Diagnostic("method", CONTEXT_NAME, "alice");
            policy.defer(diagnostic);
            policy.onAuthenticationRequestFailure(user, mock(HttpMessage.class));
        }
        // Then
        verify(pm, times(3)).makePersistent(any(Diagnostic.class));
        verify(pm, times(1)).deletePersistent(any());
    }

    @Test
    void shouldIgnoreOutcomeWithoutPendingDiagnostic() {
        // Given
        policy.configure(CONTEXT_NAME, Mode.AUTH_ON_FAILURE, 5);
        User user = userNamed("alice");
        // When
        policy.onAuthenticationRequestFailure(user, mock(HttpMessage.class));
        // Then
        verify(pm, never()).makePersistent(any());
    }
}
