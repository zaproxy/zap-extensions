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
package org.zaproxy.addon.insights.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.insights.ExtensionInsights;
import org.zaproxy.zap.testutils.TestUtils;

public class InsightsUnitTest extends TestUtils {

    private Insights insights;

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionInsights());
    }

    @BeforeEach
    void setup() {
        insights = new Insights();
    }

    @Test
    void shouldRecordNewInsights() {
        // Given
        insights.recordInsight(
                new Insight("https://example2.com", "insight.test.2-2", "Test Insight 2", 2L));
        insights.recordInsight(
                new Insight("https://example1.com", "insight.test.1-1", "Test Insight 1", 1L));
        insights.recordInsight(
                new Insight("https://example1.com", "insight.test.1-2", "Test Insight 2", 2L));
        insights.recordInsight(
                new Insight("https://example2.com", "insight.test.2-1", "Test Insight 1", 1L));

        // When
        List<Insight> list = insights.getInsightList();

        // Then
        assertThat(list.size(), is(equalTo(4)));
        assertThat(list.get(0).getKey(), is(equalTo("insight.test.1-1")));
        assertThat(list.get(1).getKey(), is(equalTo("insight.test.1-2")));
        assertThat(list.get(2).getKey(), is(equalTo("insight.test.2-1")));
        assertThat(list.get(3).getKey(), is(equalTo("insight.test.2-2")));
    }

    @Test
    void shouldReplaceOldInsights() {
        // Given
        insights.recordInsight(
                new Insight("https://example1.com", "insight.test.1-1", "Test Insight 1", 1L));
        insights.recordInsight(
                new Insight("https://example1.com", "insight.test.1-2", "Test Insight 2", 2L));
        insights.recordInsight(
                new Insight("https://example2.com", "insight.test.2-1", "Test Insight 1", 1L));
        insights.recordInsight(
                new Insight("https://example2.com", "insight.test.2-2", "Test Insight 2", 2L));

        // When
        insights.recordInsight(
                new Insight(
                        Insight.Level.LOW,
                        Insight.Reason.INFO,
                        "https://example2.com",
                        "insight.test.1-2",
                        "Test Insight 2",
                        2L,
                        false));
        insights.recordInsight(
                new Insight("https://example2.com", "insight.test.2-1", "Test Insight 1", 4L));

        List<Insight> list = insights.getInsightList();

        // Then
        assertThat(list.size(), is(equalTo(5)));
        assertThat(list.get(0).getKey(), is(equalTo("insight.test.1-2")));
        assertThat(list.get(0).getLevel(), is(equalTo(Insight.Level.LOW)));
        assertThat(list.get(0).getSite(), is(equalTo("https://example2.com")));

        assertThat(list.get(1).getKey(), is(equalTo("insight.test.1-1")));
        assertThat(list.get(1).getLevel(), is(equalTo(Insight.Level.INFO)));
        assertThat(list.get(1).getSite(), is(equalTo("https://example1.com")));

        assertThat(list.get(2).getKey(), is(equalTo("insight.test.1-2")));
        assertThat(list.get(2).getLevel(), is(equalTo(Insight.Level.INFO)));
        assertThat(list.get(2).getSite(), is(equalTo("https://example1.com")));

        assertThat(list.get(3).getKey(), is(equalTo("insight.test.2-1")));
        assertThat(list.get(3).getLevel(), is(equalTo(Insight.Level.INFO)));
        assertThat(list.get(3).getSite(), is(equalTo("https://example2.com")));
        assertThat(list.get(3).getStatistic(), is(equalTo(4L)));

        assertThat(list.get(4).getKey(), is(equalTo("insight.test.2-2")));
        assertThat(list.get(4).getLevel(), is(equalTo(Insight.Level.INFO)));
        assertThat(list.get(4).getSite(), is(equalTo("https://example2.com")));
    }

    @Test
    void shouldReportAddedInsights() {
        // Given
        InsightsTableModel model = mock(InsightsTableModel.class);
        insights.setModel(model);

        // When
        insights.recordInsight(
                new Insight("https://example1.com", "insight.test.1-1", "Test Insight 1", 1L));

        // Then
        verify(model, times(1)).insightChanged(0, true);
    }

    @Test
    void shouldReportReplacedInsights() {
        // Given
        insights.recordInsight(
                new Insight("https://example1.com", "insight.test.1-1", "Test Insight 1", 1L));
        insights.recordInsight(
                new Insight("https://example1.com", "insight.test.1-2", "Test Insight 2", 2L));
        insights.recordInsight(
                new Insight("https://example2.com", "insight.test.2-1", "Test Insight 1", 1L));
        insights.recordInsight(
                new Insight("https://example2.com", "insight.test.2-2", "Test Insight 2", 2L));

        InsightsTableModel model = mock(InsightsTableModel.class);
        insights.setModel(model);

        // When
        insights.recordInsight(
                new Insight("https://example1.com", "insight.test.1-2", "Test Insight 1", 5L));

        // Then
        verify(model, times(1)).insightChanged(1, false);
    }

    @Test
    void shouldNotReportDuplicateInsight() {
        // Given
        insights.recordInsight(
                new Insight("https://example1.com", "insight.test.1-1", "Test Insight 1", 1L));

        InsightsTableModel model = mock(InsightsTableModel.class);
        insights.setModel(model);

        // When
        insights.recordInsight(
                new Insight("https://example1.com", "insight.test.1-1", "Test Insight 1", 1L));

        // Then
        verify(model, times(0)).insightChanged(anyInt(), anyBoolean());
    }
}
