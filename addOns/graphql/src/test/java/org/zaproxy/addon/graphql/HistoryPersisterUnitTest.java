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
package org.zaproxy.addon.graphql;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.RETURNS_MOCKS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Stats;

class HistoryPersisterUnitTest extends TestUtils {

    private InMemoryStats stats;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();

        HistoryReference.setTableHistory(
                mock(
                        TableHistory.class,
                        withSettings()
                                .defaultAnswer(RETURNS_MOCKS)
                                .strictness(Strictness.LENIENT)));
        HistoryReference.setTableAlert(
                mock(
                        TableAlert.class,
                        withSettings()
                                .defaultAnswer(RETURNS_MOCKS)
                                .strictness(Strictness.LENIENT)));

        stats = new InMemoryStats();
        Stats.addListener(stats);
    }

    @AfterEach
    void cleanUp() {
        HistoryReference.setTableHistory(null);
        HistoryReference.setTableAlert(null);
    }

    @Test
    void shouldIncrementMessagesAddedStatOnSuccess() throws Exception {
        // Given
        HistoryPersister historyPersister = new HistoryPersister();
        HttpMessage message = mock(HttpMessage.class, withSettings().defaultAnswer(RETURNS_MOCKS));
        // When
        historyPersister.handleMessage(message, 1);
        // Then
        assertThat(stats.getStat(GraphQlStats.MESSAGES_ADDED), is(1L));
    }
}
