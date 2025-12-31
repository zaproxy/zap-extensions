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
package org.zaproxy.addon.insights.report;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.insights.ExtensionInsights;
import org.zaproxy.addon.insights.internal.Insight;
import org.zaproxy.addon.insights.internal.Insights;
import org.zaproxy.addon.insights.report.ExtensionInsightsReport.InsightsReportDataHandler;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ExtensionInsightsReport}. */
public class ExtensionInsightsReportUnitTest {

    /** Unit test for {@link InsightsReportDataHandler}. */
    static class InsightsReportDataHandlerUnitTest extends TestUtils {

        private InsightsReportDataHandler handler;
        private ExtensionInsights extensionInsights;

        @BeforeEach
        void beforeEach() {
            extensionInsights = mock();

            ExtensionLoader extensionLoader = mock();
            Control.initSingletonForTesting(mock(Model.class), extensionLoader);
            given(extensionLoader.getExtension(ExtensionInsights.class))
                    .willReturn(extensionInsights);
            handler = new InsightsReportDataHandler();
        }

        @Test
        void shouldNotFailToIterateReportObjectWhileModifyingOriginalInsights() {
            // Given
            List<Insight> originalInsights = new Insights().getInsightList();
            originalInsights.add(mock(Insight.class));
            originalInsights.add(mock(Insight.class));
            given(extensionInsights.getInsights()).willReturn(originalInsights);
            ReportData reportData = new ReportData("");
            handler.handle(reportData);
            // When / Then
            assertDoesNotThrow(
                    () -> {
                        for (Object unused :
                                (List<?>)
                                        reportData.getReportObject(
                                                ExtensionInsightsReport.INSIGHTS_LIST)) {
                            originalInsights.add(mock(Insight.class));
                        }
                    });
        }
    }
}
