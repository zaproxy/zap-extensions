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
package org.zaproxy.zap.extension.scripts.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;

import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Transaction;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.scripts.ExtensionScriptsUI;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptFailure;
import org.zaproxy.zap.extension.scripts.internal.db.TableJdo;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for {@link ScriptAutomationFailureRecords} with a mocked {@link TableJdo} PMF. */
class ScriptAutomationFailureRecordsUnitTest extends TestUtils {

    @BeforeAll
    static void initMessages() {
        mockMessages(new ExtensionScriptsUI());
    }

    @Test
    void shouldMakePersistentEntityWithNameTypeAndMessage() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            Transaction tx = mock(Transaction.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.currentTransaction()).willReturn(tx);
            given(tx.isActive()).willReturn(false);

            ScriptJobParameters params = new ScriptJobParameters();
            params.setName("my-script");
            params.setType("standalone");

            ScriptAutomationFailureRecords.recordFromParameters(params, "script blew up");

            ArgumentCaptor<ScriptFailure> captor = ArgumentCaptor.forClass(ScriptFailure.class);
            verify(pm).makePersistent(captor.capture());
            ScriptFailure entity = captor.getValue();
            assertThat(entity.getScriptName(), is(equalTo("my-script")));
            assertThat(entity.getScriptType(), is(equalTo("standalone")));
            assertThat(entity.getMessage(), is(equalTo("script blew up")));
            assertThat(entity.getCreateTimestamp(), is(notNullValue()));
            verify(tx).begin();
            verify(tx).commit();
            verify(pm).close();
        }
    }

    @Test
    void shouldTruncateScriptNameToColumnLimit() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            Transaction tx = mock(Transaction.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.currentTransaction()).willReturn(tx);
            given(tx.isActive()).willReturn(false);

            String longName = "N".repeat(5000);
            ScriptJobParameters params = new ScriptJobParameters();
            params.setName(longName);
            params.setType("t");

            ScriptAutomationFailureRecords.recordFromParameters(params, "e");

            ArgumentCaptor<ScriptFailure> captor = ArgumentCaptor.forClass(ScriptFailure.class);
            verify(pm).makePersistent(captor.capture());
            assertThat(captor.getValue().getScriptName().length(), is(equalTo(4096)));
        }
    }

    @Test
    void shouldNotPersistWhenScriptJobActionIsNull() {
        ScriptJobParameters parameters = new ScriptJobParameters();
        parameters.setAction(null);
        AutomationProgress progress = new AutomationProgress();

        assertThat(ScriptJob.createScriptAction(parameters, progress), is(equalTo(null)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
    }
}
