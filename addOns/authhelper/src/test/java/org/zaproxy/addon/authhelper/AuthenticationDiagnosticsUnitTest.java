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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Transaction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.AuthDiagnosticsPolicy.Mode;
import org.zaproxy.addon.authhelper.AuthenticationDiagnostics.CommitMode;
import org.zaproxy.addon.authhelper.internal.db.Diagnostic;
import org.zaproxy.addon.authhelper.internal.db.TableJdo;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.users.User;

class AuthenticationDiagnosticsUnitTest extends TestUtils {

    private static final String CONTEXT_NAME = "context";

    private MockedStatic<TableJdo> tableJdo;
    private PersistenceManager pm;
    private Transaction tx;

    @BeforeEach
    void setUp() {
        Model model = mock(Model.class);
        Session session = mock(Session.class);
        given(model.getSession()).willReturn(session);
        given(session.getContext(CONTEXT_NAME)).willReturn(mock(Context.class));
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(model);

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
        AuthDiagnosticsPolicy.getInstance().clearAll();
        tableJdo.close();
    }

    @Test
    void shouldPersistOnExplicitCommit() {
        // Given / When
        try (AuthenticationDiagnostics diags =
                new AuthenticationDiagnostics(true, "method", CONTEXT_NAME, "user")) {
            // Note: diags.close() defaults to COMMIT.
            diags.close(CommitMode.COMMIT);
        }
        // Then
        verify(pm).makePersistent(any(Diagnostic.class));
        verify(tx).commit();
    }

    @Test
    void shouldNotPersistOnDiscard() {
        // Given / When
        try (AuthenticationDiagnostics diags =
                new AuthenticationDiagnostics(true, "method", CONTEXT_NAME, "user")) {
            diags.close(CommitMode.DISCARD);
        }
        // Then
        verify(pm, never()).makePersistent(any());
        verify(tx, never()).commit();
    }

    @Test
    void shouldNotPersistOnSubsequentCloseAfterDiscard() {
        // Given
        AuthenticationDiagnostics diags =
                new AuthenticationDiagnostics(true, "method", CONTEXT_NAME, "user");
        diags.close(CommitMode.DISCARD);
        // When
        diags.close();
        // Then
        verify(pm, never()).makePersistent(any());
        verify(tx, never()).commit();
    }

    @Test
    void shouldDeferToPolicyInsteadOfPersistingWhenPolicyActive() {
        // Given
        AuthDiagnosticsPolicy.getInstance().configure(CONTEXT_NAME, Mode.AUTH_ON_FAILURE, 5);
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
        AuthDiagnosticsPolicy.getInstance()
                .onAuthenticationRequestFailure(user, mock(HttpMessage.class));
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
}
