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
package org.zaproxy.addon.authhelper.report;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.nio.file.Files;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.text.StringEscapeUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.authhelper.ExtensionAuthhelper;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.addon.reports.Template;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionAuthhelperReportUnitTest extends TestUtils {

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionAuthhelper());

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        Constant.PROGRAM_VERSION = "Test Build";
    }

    private ReportData getGenericReportData(String templateName) {
        ReportData reportData = new ReportData(templateName);
        reportData.setTitle("Test Title");
        reportData.setDescription("Test Description");
        reportData.setIncludeAllConfidences(true);
        reportData.setIncludeAllRisks(true);
        reportData.setAlertTreeRootNode(new AlertNode(0, "Test"));
        return reportData;
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://example.com",
                "https://example.com",
                "https://example.com.*",
                "https://example.com/",
                "https://example.com/.*",
                "https://example.com/test123",
                "https://example.com/test123.*",
                "https://example.com?param",
            })
    void shouldReturnValidHostName(String regexStr) throws Exception {
        // Given / When / Then
        assertThat(
                ExtensionAuthhelperReport.getHostName(regexStr),
                is(equalTo("https://example.com")));
    }

    @Test
    void shouldGenerateEmptyAuthJsonReport() throws Exception {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        String templateName = "auth-report-json";
        Template template = getTemplateFromYamlFile(templateName);
        File f = File.createTempFile(templateName, template.getExtension());
        ReportData reportData = getGenericReportData(templateName);
        reportData.setSections(template.getSections());
        AuthReportData ard = new AuthReportData();
        reportData.addReportObjects("authdata", ard);

        // When
        File r = extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
        String report = new String(Files.readAllBytes(r.toPath()));
        JSONObject json = JSONObject.fromObject(report);
        JSONArray summaryItems = json.getJSONArray("summaryItems");
        JSONArray statistics = json.getJSONArray("statistics");

        // Then
        assertThat(json.getString("@programName"), is(equalTo("ZAP")));
        assertThat(json.getString("@version"), is(equalTo("Test Build")));
        assertThat(json.getString("@generated").length(), is(greaterThan(20)));
        assertThat(json.getString("afEnv"), is(equalTo("")));
        assertThat(summaryItems.size(), is(equalTo(0)));
        assertThat(statistics.size(), is(equalTo(0)));
    }

    @Test
    void shouldGenerateFilledAuthJsonReport() throws Exception {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        String templateName = "auth-report-json";
        Template template = getTemplateFromYamlFile(templateName);
        File f = File.createTempFile(templateName, template.getExtension());
        ReportData reportData = getGenericReportData(templateName);
        reportData.setSections(template.getSections());
        AuthReportData ard = new AuthReportData();
        reportData.addReportObjects("authdata", ard);

        ard.setSite("https://www.example.com");
        String afEnv =
                """
  env:
  contexts:
    - authentication:
        method: client
        parameters:
          method: autodetect
        verification:
          method: autodetect
      name: context
      sessionManagement:
        method: autodetect
      urls:
        - https://www.example.com
      users:
        - credentials:
            password: test@test.com
            username: test123
          name: test""";
        ard.setAfEnv(StringEscapeUtils.escapeJson(afEnv));
        ard.addSummaryItem(true, "summary.1", "First Item");
        ard.addSummaryItem(false, "summary.2", "Second Item");
        ard.addStatsItem("stats.auth.1", "global", 123);
        ard.addStatsItem("stats.other.1", "site", 456);
        ard.addStatsItem("stats.other.2", "site", 5678);

        // When
        File r = extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
        String report = new String(Files.readAllBytes(r.toPath()));
        JSONObject json = JSONObject.fromObject(report);
        JSONArray summaryItems = json.getJSONArray("summaryItems");
        JSONArray statistics = json.getJSONArray("statistics");

        // Then
        assertThat(json.getString("site"), is(equalTo("https://www.example.com")));
        assertThat(json.getString("afEnv"), is(equalTo(afEnv)));
        assertThat(summaryItems.size(), is(equalTo(2)));
        assertThat(summaryItems.getJSONObject(0), is(notNullValue()));
        assertThat(summaryItems.getJSONObject(0).getBoolean("passed"), is(equalTo(true)));
        assertThat(summaryItems.getJSONObject(0).getString("key"), is(equalTo("summary.1")));
        assertThat(
                summaryItems.getJSONObject(0).getString("description"), is(equalTo("First Item")));
        assertThat(summaryItems.getJSONObject(1), is(notNullValue()));
        assertThat(summaryItems.getJSONObject(1).getBoolean("passed"), is(equalTo(false)));
        assertThat(summaryItems.getJSONObject(1).getString("key"), is(equalTo("summary.2")));
        assertThat(
                summaryItems.getJSONObject(1).getString("description"), is(equalTo("Second Item")));

        assertThat(statistics.size(), is(equalTo(3)));
        assertThat(statistics.getJSONObject(0), is(notNullValue()));
        assertThat(statistics.getJSONObject(0).getString("key"), is(equalTo("stats.auth.1")));
        assertThat(statistics.getJSONObject(0).getInt("value"), is(equalTo(123)));
        assertThat(statistics.getJSONObject(1), is(notNullValue()));
        assertThat(statistics.getJSONObject(1).getString("key"), is(equalTo("stats.other.1")));
        assertThat(statistics.getJSONObject(1).getInt("value"), is(equalTo(456)));
        assertThat(statistics.getJSONObject(2), is(notNullValue()));
        assertThat(statistics.getJSONObject(2).getString("key"), is(equalTo("stats.other.2")));
        assertThat(statistics.getJSONObject(2).getInt("value"), is(equalTo(5678)));
    }

    static Template getTemplateFromYamlFile(String templateName) throws Exception {
        return new Template(
                TestUtils.getResourcePath(
                                ExtensionReports.class,
                                "/reports/" + templateName + "/template.yaml")
                        .toFile());
    }
}
