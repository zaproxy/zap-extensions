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
package org.zaproxy.addon.insights;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteMapEventPublisher;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.addon.insights.internal.Insight;
import org.zaproxy.addon.insights.internal.StatsMonitor;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventPublisher;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionInsightsUnitTest extends TestUtils {

    private static String EXAMPLE_COM = "https://example.com";

    private ExtensionInsights ext;
    private StatsMonitor sm;
    private TestEventPublisher testPublisher;

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionInsights());
    }

    @BeforeEach
    void setup() {
        ext = new ExtensionInsights();
        sm = ext.getStatsMonitor();
        testPublisher = new TestEventPublisher();
        ext.getParam().load(new ZapXmlConfiguration());
        ext.getParam().setExitAutoOnHigh(false);

        ZAP.getEventBus()
                .registerPublisher(
                        testPublisher,
                        SiteMapEventPublisher.class.getCanonicalName(),
                        SiteMapEventPublisher.SITE_NODE_ADDED_EVENT);
    }

    @AfterEach
    void tearDown() {
        Stats.removeListener(sm);
        ZAP.getEventBus().unregisterPublisher(testPublisher);
    }

    @Test
    void shouldRecordZapErrorsAndWarnings() {
        // Given
        Stats.incCounter("stats.log.error", 1);
        Stats.incCounter("stats.log.warn", 5);
        Stats.incCounter("stats.log.other", 5);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(2)));
        assertInsight(
                0,
                Insight.Level.LOW,
                Insight.Reason.WARNING,
                "",
                "insight.log.error",
                "ZAP errors logged - see the zap.log file for details",
                1L);
        assertInsight(
                1,
                Insight.Level.LOW,
                Insight.Reason.WARNING,
                "",
                "insight.log.warn",
                "ZAP warnings logged - see the zap.log file for details",
                5L);
    }

    @Test
    void shouldRecordSpaceProblems() {
        // Given
        Stats.incCounter("stats.error.database.full", 1);
        Stats.incCounter("stats.error.diskspace.full", 1);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(2)));
        assertInsight(
                0,
                Insight.Level.HIGH,
                Insight.Reason.WARNING,
                "",
                "insight.database.full",
                "Database full",
                1L);
        assertInsight(
                1,
                Insight.Level.HIGH,
                Insight.Reason.WARNING,
                "",
                "insight.diskspace.full",
                "Diskspace full",
                1L);
    }

    @Test
    void shouldRecordNetworkInfoStats() {
        // Given
        Stats.incCounter("stats.network.send.success", 1000);
        Stats.incCounter("stats.network.send.failure", 15);
        Stats.incCounter("stats.network.send.other", 8);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(1)));
        assertInsight(0, "", "insight.network.failure", "Percentage of network failures", 1L);
    }

    @Test
    void shouldRecordWarningOnNetworkLowStats() {
        // Given
        Stats.incCounter("stats.network.send.success", 1000);
        Stats.incCounter("stats.network.send.failure", 100);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(1)));
        assertInsight(
                0,
                Insight.Level.LOW,
                Insight.Reason.EXCEEDED_LOW,
                "",
                "insight.network.failure",
                "Percentage of network failures",
                9L);
    }

    @Test
    void shouldRecordWarningOnNetworkMediumStats() {
        // Given
        Stats.incCounter("stats.network.send.success", 1000);
        Stats.incCounter("stats.network.send.failure", 2000);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(1)));
        assertInsight(
                0,
                Insight.Level.MEDIUM,
                Insight.Reason.EXCEEDED_HIGH,
                "",
                "insight.network.failure",
                "Percentage of network failures",
                66L);
    }

    @Test
    void shouldRecordAuthInfoStats() {
        // Given
        Stats.incCounter(EXAMPLE_COM, "stats.auth.success", 1000);
        Stats.incCounter(EXAMPLE_COM, "stats.auth.failure", 11);
        Stats.incCounter(EXAMPLE_COM, "stats.auth.other", 8);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(1)));
        assertInsight(
                0,
                EXAMPLE_COM,
                "insight.auth.failure",
                "Percentage of authentication failures",
                1L);
    }

    @Test
    void shouldRecordWarningOnAuthLowStats() {
        // Given
        Stats.incCounter(EXAMPLE_COM, "stats.auth.success", 1000);
        Stats.incCounter(EXAMPLE_COM, "stats.auth.failure", 100);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(1)));
        assertInsight(
                0,
                Insight.Level.LOW,
                Insight.Reason.EXCEEDED_LOW,
                EXAMPLE_COM,
                "insight.auth.failure",
                "Percentage of authentication failures",
                9L);
    }

    @Test
    void shouldRecordWarningOnAuthMediumStats() {
        // Given
        Stats.incCounter(EXAMPLE_COM, "stats.auth.success", 1000);
        Stats.incCounter(EXAMPLE_COM, "stats.auth.failure", 3000);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(1)));
        assertInsight(
                0,
                Insight.Level.MEDIUM,
                Insight.Reason.EXCEEDED_HIGH,
                EXAMPLE_COM,
                "insight.auth.failure",
                "Percentage of authentication failures",
                75L);
    }

    @Test
    void shouldRecordAllStatusCodeInfoStats() {
        // Given
        Stats.incCounter(EXAMPLE_COM, "stats.code.100", 101);
        Stats.incCounter(EXAMPLE_COM, "stats.code.200", 200);
        Stats.incCounter(EXAMPLE_COM, "stats.code.201", 2);
        Stats.incCounter(EXAMPLE_COM, "stats.code.400", 4);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(3)));
        assertInsight(
                0,
                EXAMPLE_COM,
                "insight.code.1xx",
                "Percentage of responses with status code 1xx",
                32L);
        assertInsight(
                1,
                EXAMPLE_COM,
                "insight.code.2xx",
                "Percentage of responses with status code 2xx",
                65L);
        assertInsight(
                2,
                EXAMPLE_COM,
                "insight.code.4xx",
                "Percentage of responses with status code 4xx",
                1L);
    }

    @Test
    void shouldRecordWarningOnHigh400StatusCode() {
        // Given
        Stats.incCounter(EXAMPLE_COM, "stats.code.100", 1000);
        Stats.incCounter(EXAMPLE_COM, "stats.code.400", 55);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(2)));
        assertInsight(
                0,
                EXAMPLE_COM,
                "insight.code.1xx",
                "Percentage of responses with status code 1xx",
                94L);
        assertInsight(
                1,
                Insight.Level.INFO,
                Insight.Reason.EXCEEDED_LOW,
                EXAMPLE_COM,
                "insight.code.4xx",
                "Percentage of responses with status code 4xx",
                5L);
    }

    @Test
    void shouldRecordWarningOnHigh500StatusCode() {
        // Given
        Stats.incCounter(EXAMPLE_COM, "stats.code.100", 550);
        Stats.incCounter(EXAMPLE_COM, "stats.code.500", 550);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(2)));
        assertInsight(
                0,
                Insight.Level.LOW,
                Insight.Reason.EXCEEDED_HIGH,
                EXAMPLE_COM,
                "insight.code.5xx",
                "Percentage of responses with status code 5xx",
                50L);
        assertInsight(
                1,
                EXAMPLE_COM,
                "insight.code.1xx",
                "Percentage of responses with status code 1xx",
                50L);
    }

    @Test
    void shouldRecordButNotReportQuickResponseTimesStats() {
        // Given
        Stats.incCounter(EXAMPLE_COM, "stats.responseTime.2", 1000);
        Stats.incCounter(EXAMPLE_COM, "stats.responseTime.128", 5);
        Stats.incCounter(EXAMPLE_COM, "stats.responseTime.bad", 1);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(0)));
    }

    @Test
    void shouldRecordResponseTimesInfoStats() {
        // Given
        Stats.incCounter(EXAMPLE_COM, "stats.responseTime.2", 1000);
        Stats.incCounter(EXAMPLE_COM, "stats.responseTime.256", 55);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(1)));
        assertInsight(
                0,
                Insight.Level.INFO,
                Insight.Reason.EXCEEDED_LOW,
                EXAMPLE_COM,
                "insight.response.slow",
                "Percentage of slow responses",
                5L);
    }

    @Test
    void shouldRecordhResponseTimesLowStats() {
        Stats.incCounter(EXAMPLE_COM, "stats.responseTime.2", 1000);
        Stats.incCounter(EXAMPLE_COM, "stats.responseTime.32", 500);
        Stats.incCounter(EXAMPLE_COM, "stats.responseTime.256", 1500);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(1)));
        assertInsight(
                0,
                Insight.Level.LOW,
                Insight.Reason.EXCEEDED_HIGH,
                EXAMPLE_COM,
                "insight.response.slow",
                "Percentage of slow responses",
                50L);
    }

    @Test
    void shouldRecordhResponseTimesMediumStats() {
        Stats.incCounter(EXAMPLE_COM, "stats.responseTime.2", 500);
        Stats.incCounter(EXAMPLE_COM, "stats.responseTime.16", 500);
        Stats.incCounter(EXAMPLE_COM, "stats.responseTime.256", 1050);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(1)));
        assertInsight(
                0,
                Insight.Level.LOW,
                Insight.Reason.EXCEEDED_HIGH,
                EXAMPLE_COM,
                "insight.response.slow",
                "Percentage of slow responses",
                51L);
    }

    @Test
    void shouldRecordNodesAndMethodsAdded() throws Exception {
        // Given
        publishNodeAddedEvents("https://www.example1.com/", "GET", null, 10);
        publishNodeAddedEvents("https://www.example1.com/", "POST", null, 4);
        publishNodeAddedEvents("https://www.example2.com/", "GET", null, 20);
        publishNodeAddedEvents("https://www.example2.com/", "OPTIONS", null, 2);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(6)));
        assertInsight(
                0,
                "https://www.example1.com",
                "insight.endpoint.method.GET",
                "Percentage of endpoints with method GET",
                71L);
        assertInsight(
                1,
                "https://www.example1.com",
                "insight.endpoint.method.POST",
                "Percentage of endpoints with method POST",
                28L);
        assertInsight(
                2,
                "https://www.example1.com",
                "insight.endpoint.total",
                "Count of total endpoints",
                14L);
        assertInsight(
                3,
                "https://www.example2.com",
                "insight.endpoint.method.GET",
                "Percentage of endpoints with method GET",
                90L);
        assertInsight(
                4,
                "https://www.example2.com",
                "insight.endpoint.method.OPTIONS",
                "Percentage of endpoints with method OPTIONS",
                9L);
        assertInsight(
                5,
                "https://www.example2.com",
                "insight.endpoint.total",
                "Count of total endpoints",
                22L);
    }

    @Test
    void shouldRecordContentTypesAdded() throws Exception {
        // Given
        publishNodeAddedEvents("https://www.example1.com/", "GET", "text/html", 6);
        publishNodeAddedEvents(
                "https://www.example1.com/",
                "GET",
                "multipart/form-data; boundary=ExampleBoundaryString",
                4);
        publishNodeAddedEvents("https://www.example1.com/", "GET", null, 4);
        publishNodeAddedEvents("https://www.example2.com/", "GET", "text/html; utf8", 10);
        publishNodeAddedEvents("https://www.example2.com/", "GET", "application/json", 5);
        publishNodeAddedEvents(
                "https://www.example2.com/", "GET", "application/json; some other text", 5);
        publishNodeAddedEvents("https://www.example2.com/", "GET", null, 2);

        // When
        sm.processStats();

        // Then
        assertThat(ext.getInsights().size(), is(equalTo(8)));
        assertInsight(
                0,
                "https://www.example1.com",
                "insight.endpoint.ctype.multipart/form-data",
                "Percentage of endpoints with content type multipart/form-data",
                28L);
        assertInsight(
                1,
                "https://www.example1.com",
                "insight.endpoint.ctype.text/html",
                "Percentage of endpoints with content type text/html",
                42L);
        assertInsight(
                2,
                "https://www.example1.com",
                "insight.endpoint.method.GET",
                "Percentage of endpoints with method GET",
                100L);
        assertInsight(
                3,
                "https://www.example1.com",
                "insight.endpoint.total",
                "Count of total endpoints",
                14L);
        assertInsight(
                4,
                "https://www.example2.com",
                "insight.endpoint.ctype.application/json",
                "Percentage of endpoints with content type application/json",
                45L);
        assertInsight(
                5,
                "https://www.example2.com",
                "insight.endpoint.ctype.text/html",
                "Percentage of endpoints with content type text/html",
                45L);
        assertInsight(
                6,
                "https://www.example2.com",
                "insight.endpoint.method.GET",
                "Percentage of endpoints with method GET",
                100L);
        assertInsight(
                7,
                "https://www.example2.com",
                "insight.endpoint.total",
                "Count of total endpoints",
                22L);
    }

    private void assertInsight(int index, String site, String key, String desc, long stat) {
        this.assertInsight(index, Insight.Level.INFO, Insight.Reason.INFO, site, key, desc, stat);
    }

    private void assertInsight(
            int index, Insight.Level level, String site, String key, String desc, long stat) {
        this.assertInsight(index, level, Insight.Reason.INFO, site, key, desc, stat);
    }

    private void assertInsight(
            int index,
            Insight.Level level,
            Insight.Reason reason,
            String site,
            String key,
            String desc,
            long stat) {
        Insight insightTest = ext.getInsights().get(index);
        assertThat(insightTest.getLevel(), is(equalTo(level)));
        assertThat(insightTest.getReason(), is(equalTo(reason)));
        assertThat(insightTest.getSite(), is(equalTo(site)));
        assertThat(insightTest.getKey(), is(equalTo(key)));
        assertThat(insightTest.getDescription(), is(equalTo(desc)));
        assertThat(insightTest.getStatistic(), is(equalTo(stat)));
    }

    private void publishNodeAddedEvents(
            String urlPrefix, String method, String contentType, int count) throws Exception {
        for (int i = 0; i < count; i++) {
            Map<String, String> map = new HashMap<>();
            if (contentType != null) {
                map.put("contentType", contentType);
            }
            ZAP.getEventBus()
                    .publishSyncEvent(
                            testPublisher,
                            new Event(
                                    testPublisher,
                                    SiteMapEventPublisher.SITE_NODE_ADDED_EVENT,
                                    getMockTarget(urlPrefix + i, method),
                                    map));
        }
    }

    private Target getMockTarget(String url, String method) throws Exception {
        Target target = mock(Target.class);
        SiteNode sn = mock(SiteNode.class);
        HistoryReference href = mock(HistoryReference.class);
        given(href.getHistoryType()).willReturn(HistoryReference.TYPE_PROXIED);
        given(href.getMethod()).willReturn(method);
        given(href.getURI()).willReturn(new URI(url, true));
        given(sn.getHistoryReference()).willReturn(href);
        given(target.getStartNode()).willReturn(sn);
        return target;
    }

    private class TestEventPublisher implements EventPublisher {

        @Override
        public String getPublisherName() {
            return SiteMapEventPublisher.class.getCanonicalName();
        }
    }
}
