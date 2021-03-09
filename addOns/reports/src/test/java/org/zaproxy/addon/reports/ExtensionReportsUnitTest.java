/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.model.Context;

public class ExtensionReportsUnitTest {

    @Test
    public void shouldExtractExpectedParams() {
        // Given
        String pattern = ReportParam.DEFAULT_NAME_PATTERN;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

        // When
        String dateStr = sdf.format(new Date());
        String name = ExtensionReports.getNameFromPattern(pattern, "https://www.example.com");

        // Then
        assertThat(name, is(equalTo(dateStr + "-ZAP-Report-www.example.com")));
    }

    @Test
    public void shouldIncludeRelevantContextUrls() {
        // Given
        Context context = new Context(null, 1);
        context.addIncludeInContextRegex("https://www.example.com.*");
        context.addIncludeInContextRegex("https://www.example.com2/test.*");
        ReportData reportData = new ReportData(true, true);
        reportData.setContexts(Arrays.asList(context));

        Alert alert1 = new Alert(1);
        alert1.setUri("https://www.example.com/");

        Alert alert2 = new Alert(2);
        alert2.setUri("https://www.example.com/test/");

        Alert alert3 = new Alert(3);
        alert3.setUri("https://www.example.com2/test/");

        // When
        AlertNode alertNode1 = new AlertNode(-1, "Alert 1");
        alertNode1.setUserObject(alert1);
        AlertNode alertNode2 = new AlertNode(-2, "Alert 2");
        alertNode2.setUserObject(alert2);
        AlertNode alertNode3 = new AlertNode(-3, "Alert 3");
        alertNode3.setUserObject(alert3);

        // Then
        assertThat(ExtensionReports.isIncluded(reportData, alertNode1), is(equalTo(true)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode2), is(equalTo(true)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode3), is(equalTo(true)));
    }

    @Test
    public void shouldExcludeRelevantContextUrls() {
        // Given
        Context context = new Context(null, 1);
        context.addIncludeInContextRegex("https://www.example.com/.*");
        context.addIncludeInContextRegex("https://www.example.com2/test.*");
        ReportData reportData = new ReportData(true, true);
        reportData.setContexts(Arrays.asList(context));

        Alert alert1 = new Alert(1);
        alert1.setUri("https://www.example.org/");

        Alert alert2 = new Alert(2);
        alert2.setUri("http://www.example.com/test/");

        Alert alert3 = new Alert(3);
        alert3.setUri("https://www.example.com2/");

        // When
        AlertNode alertNode1 = new AlertNode(-1, "Alert 1");
        alertNode1.setUserObject(alert1);
        AlertNode alertNode2 = new AlertNode(-2, "Alert 2");
        alertNode2.setUserObject(alert2);
        AlertNode alertNode3 = new AlertNode(-3, "Alert 3");
        alertNode3.setUserObject(alert3);

        // Then
        assertThat(ExtensionReports.isIncluded(reportData, alertNode1), is(equalTo(false)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode2), is(equalTo(false)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode3), is(equalTo(false)));
    }

    @Test
    public void shouldIncludeRelevantSiteUrls() {
        // Given
        String site1 = "https://www.example.com";
        String site2 = "https://www.example.com2";

        ReportData reportData = new ReportData(true, true);
        reportData.setSites(Arrays.asList(site1, site2));

        Alert alert1 = new Alert(1);
        alert1.setUri("https://www.example.com/");

        Alert alert2 = new Alert(2);
        alert2.setUri("https://www.example.com/test/");

        Alert alert3 = new Alert(3);
        alert3.setUri("https://www.example.com2/test/");

        // When
        AlertNode alertNode1 = new AlertNode(-1, "Alert 1");
        alertNode1.setUserObject(alert1);
        AlertNode alertNode2 = new AlertNode(-2, "Alert 2");
        alertNode2.setUserObject(alert2);
        AlertNode alertNode3 = new AlertNode(-3, "Alert 3");
        alertNode3.setUserObject(alert3);

        // Then
        assertThat(ExtensionReports.isIncluded(reportData, alertNode1), is(equalTo(true)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode2), is(equalTo(true)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode3), is(equalTo(true)));
    }

    @Test
    public void shouldExcludeRelevantSiteUrls() {
        // Given
        String site1 = "https://www.example.com/";
        String site2 = "https://www.example.com2/";

        ReportData reportData = new ReportData(true, true);
        reportData.setSites(Arrays.asList(site1, site2));

        Alert alert1 = new Alert(1);
        alert1.setUri("https://www.example.org/");

        Alert alert2 = new Alert(2);
        alert2.setUri("http://www.example.com/test/");

        Alert alert3 = new Alert(3);
        alert3.setUri("https://www.example.com3/");

        // When
        AlertNode alertNode1 = new AlertNode(-1, "Alert 1");
        alertNode1.setUserObject(alert1);
        AlertNode alertNode2 = new AlertNode(-2, "Alert 2");
        alertNode2.setUserObject(alert2);
        AlertNode alertNode3 = new AlertNode(-3, "Alert 3");
        alertNode3.setUserObject(alert3);

        // Then
        assertThat(ExtensionReports.isIncluded(reportData, alertNode1), is(equalTo(false)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode2), is(equalTo(false)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode3), is(equalTo(false)));
    }

    @Test
    public void shouldIncludeRelevantContextAndSiteUrls() {
        // Given
        Context context = new Context(null, 1);
        context.addIncludeInContextRegex("https://www.example.com.*");
        context.addIncludeInContextRegex("https://www.example.com2/test.*");
        String site1 = "https://www.example.com";
        String site2 = "https://www.example.com2";

        ReportData reportData = new ReportData(true, true);
        reportData.setSites(Arrays.asList(site1, site2));
        reportData.setContexts(Arrays.asList(context));

        Alert alert1 = new Alert(1);
        alert1.setUri("https://www.example.com/");

        Alert alert2 = new Alert(2);
        alert2.setUri("https://www.example.com/test/");

        Alert alert3 = new Alert(3);
        alert3.setUri("https://www.example.com2/test/");

        // When
        AlertNode alertNode1 = new AlertNode(-1, "Alert 1");
        alertNode1.setUserObject(alert1);
        AlertNode alertNode2 = new AlertNode(-2, "Alert 2");
        alertNode2.setUserObject(alert2);
        AlertNode alertNode3 = new AlertNode(-3, "Alert 3");
        alertNode3.setUserObject(alert3);

        // Then
        assertThat(ExtensionReports.isIncluded(reportData, alertNode1), is(equalTo(true)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode2), is(equalTo(true)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode3), is(equalTo(true)));
    }

    @Test
    public void shouldExcludeRelevantContextAndSiteUrls() {
        // Given
        Context context = new Context(null, 1);
        context.addIncludeInContextRegex("https://www.example.com/.*");
        context.addIncludeInContextRegex("https://www.example.com2/test.*");
        context.addExcludeFromContextRegex("https://www.example.com/test.*");
        String site1 = "https://www.example.org";
        String site2 = "https://www.example.com3";

        ReportData reportData = new ReportData(true, true);
        reportData.setSites(Arrays.asList(site1, site2));
        reportData.setContexts(Arrays.asList(context));

        Alert alert1 = new Alert(1);
        // In sites but not in contexts
        alert1.setUri("https://www.example.org/");

        Alert alert2 = new Alert(2);
        // In sites but excluded from contexts
        alert2.setUri("https://www.example.com/test/");

        Alert alert3 = new Alert(3);
        // In context but not in sites
        alert3.setUri("https://www.example.com2/test/");

        // When
        AlertNode alertNode1 = new AlertNode(-1, "Alert 1");
        alertNode1.setUserObject(alert1);
        AlertNode alertNode2 = new AlertNode(-2, "Alert 2");
        alertNode2.setUserObject(alert2);
        AlertNode alertNode3 = new AlertNode(-3, "Alert 3");
        alertNode3.setUserObject(alert3);

        // Then
        assertThat(ExtensionReports.isIncluded(reportData, alertNode1), is(equalTo(false)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode2), is(equalTo(false)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode3), is(equalTo(false)));
    }
}
