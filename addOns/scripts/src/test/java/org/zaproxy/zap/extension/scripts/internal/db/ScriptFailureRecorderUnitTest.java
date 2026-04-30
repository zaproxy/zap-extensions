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
package org.zaproxy.zap.extension.scripts.internal.db;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import javax.jdo.PersistenceManagerFactory;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

/** Unit tests for {@link ScriptFailureRecorder} against a mocked {@link TableJdo} PMF. */
class ScriptFailureRecorderUnitTest {

    @Test
    void shouldNotTouchPersistenceWhenMessageIsBlank() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);

            ScriptFailureRecorder.record("a", "b", "  \t  ");

            verify(pmf, never()).getPersistenceManager();
        }
    }
}
