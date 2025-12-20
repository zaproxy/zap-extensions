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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.nio.file.Files;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.AutoDetectSessionManagementMethodType;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod;
import org.zaproxy.addon.authhelper.ClientScriptBasedAuthenticationMethodType;
import org.zaproxy.addon.authhelper.ClientScriptBasedAuthenticationMethodType.ClientScriptBasedAuthenticationMethod;
import org.zaproxy.addon.authhelper.ExtensionAuthhelper;
import org.zaproxy.addon.authhelper.HeaderBasedSessionManagementMethodType;
import org.zaproxy.addon.authhelper.internal.db.Diagnostic;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticStep;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticWebElement;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticWebElement.SelectorType;
import org.zaproxy.addon.authhelper.report.AuthReportData.FailureDetail;
import org.zaproxy.addon.authhelper.report.AuthReportData.StatsItem;
import org.zaproxy.addon.authhelper.report.AuthReportData.SummaryItem;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.addon.reports.Template;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthCheckingStrategy;
import org.zaproxy.zap.authentication.ManualAuthenticationMethodType;
import org.zaproxy.zap.authentication.ManualAuthenticationMethodType.ManualAuthenticationMethod;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionAuthhelperReportUnitTest extends TestUtils {

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionAuthhelper());

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(model, extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        Constant.PROGRAM_VERSION = "Test Build";
    }

    private static ReportData getGenericReportData(String templateName) {
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
        assertThat(json.getString("afEnv"), is(equalTo("null")));
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
        ard.setAfEnv(afEnv);
        ard.addSummaryItem(true, "summary.1", "First Item");
        ard.addSummaryItem(false, "summary.2", "Second Item");
        ard.addFailureDetail(FailureDetail.NO_SUCCESSFUL_LOGINS);
        ard.addStatsItem("stats.auth.1", "global", 123);
        ard.addStatsItem("stats.other.1", "site", 456);
        ard.addStatsItem("stats.other.2", "site", 5678);

        // When
        File r = extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
        String report = new String(Files.readAllBytes(r.toPath()));
        JSONObject json = JSONObject.fromObject(report);
        JSONArray summaryItems = json.getJSONArray("summaryItems");
        JSONArray statistics = json.getJSONArray("statistics");
        JSONArray failureReasons = json.getJSONArray("failureReasons");

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

        assertThat(failureReasons.size(), is(equalTo(1)));
        assertThat(
                failureReasons.getJSONObject(0).getString("key"),
                is(equalTo(FailureDetail.NO_SUCCESSFUL_LOGINS.getKey())));
        assertThat(
                failureReasons.getJSONObject(0).getString("description"),
                is(equalTo("No successful logins.")));

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

    @Test
    void shouldGenerateFilledAuthJsonReportHandlingSpecialCharacters() throws Exception {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        String templateName = "auth-report-json";
        Template template = getTemplateFromYamlFile(templateName);
        File f = File.createTempFile(templateName, template.getExtension());
        ReportData reportData = getGenericReportData(templateName);
        reportData.setSections(template.getSections());
        AuthReportData ard = mock();
        reportData.addReportObjects("authdata", ard);

        given(ard.getSite()).willReturn("https://www.example.com");
        String afEnv =
                """
                  env:
                  contexts:
                      name: 'some "quote" name'
                """;
        given(ard.getAfEnv()).willReturn(afEnv);
        given(ard.getSummaryItems())
                .willReturn(
                        List.of(
                                new SummaryItem(true, "summary.1", "Bob's \"Item\""),
                                new SummaryItem(true, "summary.\"2\"", "Foo bar")));
        given(ard.getStatistics())
                .willReturn(
                        List.of(
                                        new StatsItem("stats.auth.1", "foo \"random\" bar", 123),
                                        new StatsItem("stats.foo.oops \"foo\" bar", "global", 0))
                                .toArray());
        given(ard.getLogContent()).willReturn("Log content");
        // When
        File r = extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
        String report = Files.readString(r.toPath());

        // Then
        String expected =
                """
                {
                	"@programName": "ZAP",
                	"@version": "Test Build",
                	"@generated": "",
                	"site":  "https:\\/\\/www.example.com"
                \t
                	,"summaryItems": [
                		{
                			"description": "Bob's \\\"Item\\\"",
                			"passed": true,
                			"key": "summary.1"
                		},
                		{
                			"description": "Foo bar",
                			"passed": true,
                			"key": "summary.\\\"2\\\""
                		}
                	]
                \t
                \t
                \t
                	,"afEnv": "  env:\\n  contexts:\\n      name: 'some \\\"quote\\\" name'\\n"
                \t
                	,"afPlanErrors": [\n\t]
                \t
                	,"statistics": [
                		{
                			"key": "stats.auth.1",
                			"scope": "foo \\\"random\\\" bar",
                			"value": 123
                		},
                		{
                			"key": "stats.foo.oops \\\"foo\\\" bar",
                			"scope": "global",
                			"value": 0
                		}
                	]
                	,"domains": [
                	]
                	,"domainsPartiallyOutOfScope": [
                	]
                	,"domainsOutOfScope": [
                	]
                	,"logFile": "Log content"
                	,\"diagnostics\": [
                	]
                }
                """;
        assertThat(
                report.replaceFirst("@generated\": \"[^\"]+\"", "@generated\": \"\""),
                is(equalTo(expected)));
    }

    static Template getTemplateFromYamlFile(String templateName) throws Exception {
        return new Template(
                TestUtils.getResourcePath(
                                ExtensionReports.class,
                                "/reports/" + templateName + "/template.yaml")
                        .toFile());
    }

    @Test
    void shouldIncludeDiagnosticsDataInReport() throws Exception {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        String templateName = "auth-report-json";
        Template template = getTemplateFromYamlFile(templateName);
        File f = File.createTempFile(templateName, template.getExtension());
        ReportData reportData = getGenericReportData(templateName);
        reportData.setSections(template.getSections());
        AuthReportData ard = mock();
        List<Diagnostic> diagnostics = new ArrayList<>();
        Diagnostic diagnostic = new Diagnostic();
        diagnostic.setCreateTimestamp(Instant.ofEpochMilli(1L));
        diagnostic.setAuthenticationMethod("AuthenticationMethod 1");
        diagnostic.setContext("Context 1");
        diagnostic.setUser("User 1");
        diagnostic.setScript("Script");
        diagnostic.setAfPlan("AF Plan 1");
        diagnostics.add(diagnostic);

        diagnostic = new Diagnostic();
        diagnostic.setCreateTimestamp(Instant.ofEpochMilli(2L));
        diagnostic.setAuthenticationMethod("AuthenticationMethod 2");
        diagnostic.setContext("Context 2");
        diagnostic.setUser("User 2");

        List<DiagnosticStep> steps = new ArrayList<>();
        DiagnosticStep step = new DiagnosticStep();
        step.setCreateTimestamp(Instant.ofEpochMilli(3L));
        step.setId(123);
        step.setUrl("http://example.com");
        step.setDescription("Step Description");

        DiagnosticWebElement webElement = new DiagnosticWebElement();
        webElement.setCreateTimestamp(Instant.ofEpochMilli(4L));
        webElement.setId(1);
        webElement.setFormIndex(2);
        webElement.setSelectorType(SelectorType.CSS);
        webElement.setSelectorValue("x > y");
        webElement.setFormIndex(1);
        webElement.setTagName("Tag Name");
        webElement.setAttributeType("Attribute Type");
        webElement.setAttributeId("Attribute ID");
        webElement.setAttributeValue("Attribute Value");
        webElement.setText("Text");
        webElement.setDisplayed(true);
        webElement.setEnabled(true);
        step.setWebElement(webElement);

        steps.add(step);
        diagnostic.setSteps(steps);
        diagnostics.add(diagnostic);

        given(ard.getDiagnostics()).willReturn(diagnostics);
        reportData.addReportObjects("authdata", ard);

        // When
        extRep.generateReport(reportData, template, f.getAbsolutePath(), false);

        // Then
        assertThat(
                Files.readString(f.toPath()).replaceAll("[\t\n]+", " "),
                containsString(
                        """
	,"diagnostics": [
		{
			"created": "1970-01-01T00:00:00.001Z",
			"authenticationMethod": "AuthenticationMethod 1",
			"context": "Context 1",
			"user": "User 1",
			"script": "Script"
			,"afPlan": "AF Plan 1"

			,"steps": [
			]
		},
		{
			"created": "1970-01-01T00:00:00.002Z",
			"authenticationMethod": "AuthenticationMethod 2",
			"context": "Context 2",
			"user": "User 2",
			"script": null
			,"afPlan": null

			,"steps": [
				{
					"id": 123,
					"created": "1970-01-01T00:00:00.003Z",
					"url": "http:\\/\\/example.com",
					"description": "Step Description"

					,"webElement": {
						"selector": {"type": "CSS", "value": "x > y"},
						"formIndex": 1,
						"tagName": "Tag Name",
						"attributeType":  "Attribute Type",
						"attributeId": "Attribute ID",
						"attributeName": null,
						"attributeValue":  "Attribute Value",
						"text":  "Text",
						"displayed": true,
						"enabled": true
					}

					,"webElements": [
					]
					,"localStorage": [
					]
					,"sessionStorage": [
					]
					,"messages": [
					]
				}
			]
		}
	]
"""
                                .replaceAll("[\t\n]+", " ")));
    }

    @Test
    void shouldIgnoreNonAuthReport() {
        // Given
        ExtensionAuthhelperReport.AuthReportDataHandler dataHandler =
                new ExtensionAuthhelperReport.AuthReportDataHandler();
        ReportData reportData = new ReportData("some-other-report");

        // When
        dataHandler.handle(reportData);

        // Then
        assertThat(reportData.getReportObject("authdata"), is(nullValue()));
    }

    @Test
    void shouldNotErrorIfNoContexts() {
        // Given
        ExtensionAuthhelperReport.AuthReportDataHandler dataHandler =
                new ExtensionAuthhelperReport.AuthReportDataHandler();
        ReportData reportData = new ReportData("auth-report-test");
        reportData.setContexts(List.of());

        // When
        dataHandler.handle(reportData);

        // Then
        assertThat(reportData.getReportObject("authdata"), is(notNullValue()));
        AuthReportData ard = (AuthReportData) reportData.getReportObject("authdata");
        assertThat(ard.isValidReport(), is(equalTo(false)));
        assertThat(ard.getSummaryItems().size(), is(equalTo(0)));
    }

    @Test
    void shouldReportPassingCase() {
        // Given
        String site = "https://www.example.com";
        ExtensionAuthhelperReport.AuthReportDataHandler dataHandler =
                new ExtensionAuthhelperReport.AuthReportDataHandler();
        ReportData reportData = new ReportData("auth-report-test");
        Context context = mock(Context.class);
        given(context.getAuthenticationMethod())
                .willReturn(
                        new BrowserBasedAuthenticationMethodType().createAuthenticationMethod(0));
        given(context.getIncludeInContextRegexs()).willReturn(List.of(site + ".*"));
        reportData.setContexts(List.of(context));

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionStats extStats =
                mock(ExtensionStats.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);

        InMemoryStats stats = new InMemoryStats();
        given(extStats.getInMemoryStats()).willReturn(stats);

        stats.counterInc(site, AuthUtils.AUTH_BROWSER_PASSED_STATS);
        stats.counterInc(site, AuthenticationHelper.AUTH_SUCCESS_STATS);

        stats.counterInc(site, AuthenticationMethod.AUTH_STATE_LOGGED_IN_STATS, 1);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        // When
        dataHandler.handle(reportData);

        // Then
        assertThat(reportData.getReportObject("authdata"), is(notNullValue()));
        AuthReportData ard = (AuthReportData) reportData.getReportObject("authdata");
        assertThat(ard.isValidReport(), is(equalTo(true)));
        assertThat(ard.getSummaryItems().size(), is(equalTo(5)));

        assertThat(ard.getSummaryItems().get(0).key(), is(equalTo("auth.summary.auth")));
        assertThat(ard.getSummaryItems().get(0).passed(), is(equalTo(true)));

        assertThat(ard.getSummaryItems().get(1).key(), is(equalTo("auth.summary.username")));
        assertThat(ard.getSummaryItems().get(1).passed(), is(equalTo(true)));

        assertThat(ard.getSummaryItems().get(2).key(), is(equalTo("auth.summary.password")));
        assertThat(ard.getSummaryItems().get(2).passed(), is(equalTo(true)));

        assertThat(ard.getSummaryItems().get(3).key(), is(equalTo("auth.summary.session")));
        assertThat(ard.getSummaryItems().get(3).passed(), is(equalTo(true)));

        assertThat(ard.getSummaryItems().get(4).key(), is(equalTo("auth.summary.verif")));
        assertThat(ard.getSummaryItems().get(4).passed(), is(equalTo(true)));

        assertThat(ard.getFailureDetails(), is(is(nullValue())));

        assertThat(ard.getAfPlanErrors().size(), is(equalTo(0)));
    }

    @Test
    void shouldReportFailingWithUnknownLoggedInState() {
        // Given
        String site = "https://www.example.com";
        ExtensionAuthhelperReport.AuthReportDataHandler dataHandler =
                new ExtensionAuthhelperReport.AuthReportDataHandler();
        ReportData reportData = new ReportData("auth-report-test");
        Context context = mock(Context.class);
        given(context.getAuthenticationMethod())
                .willReturn(
                        new BrowserBasedAuthenticationMethodType().createAuthenticationMethod(0));
        given(context.getIncludeInContextRegexs()).willReturn(List.of(site + ".*"));
        reportData.setContexts(List.of(context));

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionStats extStats =
                mock(ExtensionStats.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);

        InMemoryStats stats = new InMemoryStats();
        given(extStats.getInMemoryStats()).willReturn(stats);

        stats.counterInc(site, AuthUtils.AUTH_BROWSER_PASSED_STATS);
        stats.counterInc(site, AuthenticationHelper.AUTH_SUCCESS_STATS);

        stats.counterInc(site, AuthenticationMethod.AUTH_STATE_UNKNOWN_STATS, 1);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        // When
        dataHandler.handle(reportData);

        // Then
        assertThat(reportData.getReportObject("authdata"), is(notNullValue()));
        AuthReportData ard = (AuthReportData) reportData.getReportObject("authdata");
        assertThat(ard.isValidReport(), is(equalTo(true)));
        assertThat(ard.getSummaryItems().size(), is(equalTo(5)));

        assertThat(ard.getSummaryItems().get(0).key(), is(equalTo("auth.summary.auth")));
        assertThat(ard.getSummaryItems().get(0).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(1).key(), is(equalTo("auth.summary.username")));
        assertThat(ard.getSummaryItems().get(1).passed(), is(equalTo(true)));

        assertThat(ard.getSummaryItems().get(2).key(), is(equalTo("auth.summary.password")));
        assertThat(ard.getSummaryItems().get(2).passed(), is(equalTo(true)));

        assertThat(ard.getSummaryItems().get(3).key(), is(equalTo("auth.summary.session")));
        assertThat(ard.getSummaryItems().get(3).passed(), is(equalTo(true)));

        assertThat(ard.getSummaryItems().get(4).key(), is(equalTo("auth.summary.verif")));
        assertThat(ard.getSummaryItems().get(4).passed(), is(equalTo(true)));

        assertThat(ard.getFailureDetails(), contains(FailureDetail.LOGGED_IN));

        assertThat(ard.getAfPlanErrors().size(), is(equalTo(0)));
    }

    @Test
    void shouldReportFailingBbaCase() {
        // Given
        String site = "https://www.example.com";
        ExtensionAuthhelperReport.AuthReportDataHandler dataHandler =
                new ExtensionAuthhelperReport.AuthReportDataHandler();
        ReportData reportData = new ReportData("auth-report-test");
        Context context = mock(Context.class);

        BrowserBasedAuthenticationMethod authMethod =
                new BrowserBasedAuthenticationMethodType().createAuthenticationMethod(0);
        authMethod.setAuthCheckingStrategy(AuthCheckingStrategy.AUTO_DETECT);
        given(context.getAuthenticationMethod()).willReturn(authMethod);
        given(context.getSessionManagementMethod())
                .willReturn(
                        new AutoDetectSessionManagementMethodType()
                                .createSessionManagementMethod(0));

        given(context.getIncludeInContextRegexs()).willReturn(List.of(site + ".*"));
        reportData.setContexts(List.of(context));

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionStats extStats =
                mock(ExtensionStats.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);

        InMemoryStats stats = new InMemoryStats();
        given(extStats.getInMemoryStats()).willReturn(stats);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        // When
        dataHandler.handle(reportData);

        // Then
        assertThat(reportData.getReportObject("authdata"), is(notNullValue()));
        AuthReportData ard = (AuthReportData) reportData.getReportObject("authdata");
        assertThat(ard.isValidReport(), is(equalTo(true)));
        assertThat(ard.getSummaryItems().size(), is(equalTo(5)));

        assertThat(ard.getSummaryItems().get(0).key(), is(equalTo("auth.summary.auth")));
        assertThat(ard.getSummaryItems().get(0).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(1).key(), is(equalTo("auth.summary.username")));
        assertThat(ard.getSummaryItems().get(1).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(2).key(), is(equalTo("auth.summary.password")));
        assertThat(ard.getSummaryItems().get(2).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(3).key(), is(equalTo("auth.summary.session")));
        assertThat(ard.getSummaryItems().get(3).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(4).key(), is(equalTo("auth.summary.verif")));
        assertThat(ard.getSummaryItems().get(4).passed(), is(equalTo(false)));

        assertThat(ard.getAfPlanErrors().size(), is(equalTo(0)));
    }

    @Test
    void shouldReportFailingClientCase() {
        // Given
        String site = "https://www.example.com";
        ExtensionAuthhelperReport.AuthReportDataHandler dataHandler =
                new ExtensionAuthhelperReport.AuthReportDataHandler();
        ReportData reportData = new ReportData("auth-report-test");
        Context context = mock(Context.class);

        ClientScriptBasedAuthenticationMethod authMethod =
                new ClientScriptBasedAuthenticationMethodType().createAuthenticationMethod(0);
        authMethod.setAuthCheckingStrategy(AuthCheckingStrategy.AUTO_DETECT);
        given(context.getAuthenticationMethod()).willReturn(authMethod);
        given(context.getSessionManagementMethod())
                .willReturn(
                        new AutoDetectSessionManagementMethodType()
                                .createSessionManagementMethod(0));

        given(context.getIncludeInContextRegexs()).willReturn(List.of(site + ".*"));
        reportData.setContexts(List.of(context));

        AutomationProgress afProg = new AutomationProgress();
        afProg.error("It's all gone horribly wrong");
        reportData.addReportObjects("automation.progress", afProg);

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionStats extStats =
                mock(ExtensionStats.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);

        InMemoryStats stats = new InMemoryStats();
        given(extStats.getInMemoryStats()).willReturn(stats);

        stats.counterInc(site, AuthenticationHelper.AUTH_SUCCESS_STATS, 1);
        stats.counterInc(site, AuthenticationHelper.AUTH_FAILURE_STATS, 2);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        // When
        dataHandler.handle(reportData);

        // Then
        assertThat(reportData.getReportObject("authdata"), is(notNullValue()));
        AuthReportData ard = (AuthReportData) reportData.getReportObject("authdata");
        assertThat(ard.isValidReport(), is(equalTo(true)));
        assertThat(ard.getSummaryItems().size(), is(equalTo(3)));

        assertThat(ard.getSummaryItems().get(0).key(), is(equalTo("auth.summary.auth")));
        assertThat(ard.getSummaryItems().get(0).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(1).key(), is(equalTo("auth.summary.session")));
        assertThat(ard.getSummaryItems().get(1).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(2).key(), is(equalTo("auth.summary.verif")));
        assertThat(ard.getSummaryItems().get(2).passed(), is(equalTo(false)));

        assertThat(
                ard.getFailureDetails(),
                contains(
                        FailureDetail.SESSION_MGMT,
                        FailureDetail.VERIF_IDENT,
                        FailureDetail.PASS_COUNT,
                        FailureDetail.LOGIN_FAILURES,
                        FailureDetail.AF_PLAN_ERRORS,
                        FailureDetail.LOGGED_IN));

        assertThat(ard.getAfPlanErrors().size(), is(equalTo(1)));
        assertThat(ard.getAfPlanErrors().get(0), is(equalTo("It's all gone horribly wrong")));
    }

    @Test
    void shouldReportPassingClientCase() {
        // Given
        String site = "https://www.example.com";
        ExtensionAuthhelperReport.AuthReportDataHandler dataHandler =
                new ExtensionAuthhelperReport.AuthReportDataHandler();
        ReportData reportData = new ReportData("auth-report-test");
        Context context = mock(Context.class);

        ClientScriptBasedAuthenticationMethod authMethod =
                new ClientScriptBasedAuthenticationMethodType().createAuthenticationMethod(0);
        authMethod.setAuthCheckingStrategy(AuthCheckingStrategy.POLL_URL);
        given(context.getAuthenticationMethod()).willReturn(authMethod);
        given(context.getSessionManagementMethod())
                .willReturn(
                        new HeaderBasedSessionManagementMethodType()
                                .createSessionManagementMethod(0));

        given(context.getIncludeInContextRegexs()).willReturn(List.of(site + ".*"));
        reportData.setContexts(List.of(context));

        AutomationProgress afProg = new AutomationProgress();
        reportData.addReportObjects("automation.progress", afProg);

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionStats extStats =
                mock(ExtensionStats.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);

        InMemoryStats stats = new InMemoryStats();
        given(extStats.getInMemoryStats()).willReturn(stats);

        stats.counterInc(site, AuthenticationHelper.AUTH_SUCCESS_STATS, 2);
        stats.counterInc(site, AuthenticationHelper.AUTH_FAILURE_STATS, 1);

        stats.counterInc(site, AuthenticationMethod.AUTH_STATE_LOGGED_IN_STATS, 1);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        // When
        dataHandler.handle(reportData);

        // Then
        assertThat(reportData.getReportObject("authdata"), is(notNullValue()));
        AuthReportData ard = (AuthReportData) reportData.getReportObject("authdata");
        assertThat(ard.isValidReport(), is(equalTo(true)));
        assertThat(ard.getSummaryItems().size(), is(equalTo(3)));

        assertThat(ard.getSummaryItems().get(0).key(), is(equalTo("auth.summary.auth")));
        assertThat(ard.getSummaryItems().get(0).passed(), is(equalTo(true)));

        assertThat(ard.getSummaryItems().get(1).key(), is(equalTo("auth.summary.session")));
        assertThat(ard.getSummaryItems().get(1).passed(), is(equalTo(true)));

        assertThat(ard.getSummaryItems().get(2).key(), is(equalTo("auth.summary.verif")));
        assertThat(ard.getSummaryItems().get(2).passed(), is(equalTo(true)));

        assertThat(ard.getFailureDetails(), is(is(nullValue())));

        assertThat(ard.getAfPlanErrors().size(), is(equalTo(0)));
    }

    @Test
    void shouldReportWithManualAuth() {
        // Given
        ExtensionAuthhelperReport.AuthReportDataHandler dataHandler =
                new ExtensionAuthhelperReport.AuthReportDataHandler();
        ReportData reportData = new ReportData("auth-report-test");
        Context context = mock(Context.class);

        ManualAuthenticationMethod authMethod =
                new ManualAuthenticationMethodType().createAuthenticationMethod(0);
        given(context.getAuthenticationMethod()).willReturn(authMethod);

        reportData.setContexts(List.of(context));

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionStats extStats =
                mock(ExtensionStats.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);

        InMemoryStats stats = new InMemoryStats();
        given(extStats.getInMemoryStats()).willReturn(stats);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        // When
        dataHandler.handle(reportData);

        // Then
        assertThat(reportData.getReportObject("authdata"), is(notNullValue()));
        AuthReportData ard = (AuthReportData) reportData.getReportObject("authdata");
        assertThat(ard.isValidReport(), is(equalTo(false)));
        assertThat(ard.getSummaryItems().size(), is(equalTo(0)));
    }

    @Test
    void shouldReportWithNoRegexes() {
        // Given
        ExtensionAuthhelperReport.AuthReportDataHandler dataHandler =
                new ExtensionAuthhelperReport.AuthReportDataHandler();
        ReportData reportData = new ReportData("auth-report-test");
        Context context = mock(Context.class);

        BrowserBasedAuthenticationMethod authMethod =
                new BrowserBasedAuthenticationMethodType().createAuthenticationMethod(0);
        authMethod.setAuthCheckingStrategy(AuthCheckingStrategy.AUTO_DETECT);
        given(context.getAuthenticationMethod()).willReturn(authMethod);
        given(context.getSessionManagementMethod())
                .willReturn(
                        new AutoDetectSessionManagementMethodType()
                                .createSessionManagementMethod(0));

        reportData.setContexts(List.of(context));

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionStats extStats =
                mock(ExtensionStats.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);

        InMemoryStats stats = new InMemoryStats();
        given(extStats.getInMemoryStats()).willReturn(stats);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        // When
        dataHandler.handle(reportData);

        // Then
        assertThat(reportData.getReportObject("authdata"), is(notNullValue()));
        AuthReportData ard = (AuthReportData) reportData.getReportObject("authdata");
        assertThat(ard.isValidReport(), is(equalTo(true)));
        assertThat(ard.getSummaryItems().size(), is(equalTo(3)));

        assertThat(ard.getSummaryItems().get(0).key(), is(equalTo("auth.summary.stats")));
        assertThat(ard.getSummaryItems().get(0).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(1).key(), is(equalTo("auth.summary.session")));
        assertThat(ard.getSummaryItems().get(1).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(2).key(), is(equalTo("auth.summary.verif")));
        assertThat(ard.getSummaryItems().get(2).passed(), is(equalTo(false)));
    }

    @Test
    void shouldReportWithNoStats() {
        // Given
        String site = "https://www.example.com";
        ExtensionAuthhelperReport.AuthReportDataHandler dataHandler =
                new ExtensionAuthhelperReport.AuthReportDataHandler();
        ReportData reportData = new ReportData("auth-report-test");
        Context context = mock(Context.class);

        BrowserBasedAuthenticationMethod authMethod =
                new BrowserBasedAuthenticationMethodType().createAuthenticationMethod(0);
        authMethod.setAuthCheckingStrategy(AuthCheckingStrategy.AUTO_DETECT);
        given(context.getAuthenticationMethod()).willReturn(authMethod);
        given(context.getSessionManagementMethod())
                .willReturn(
                        new AutoDetectSessionManagementMethodType()
                                .createSessionManagementMethod(0));

        given(context.getIncludeInContextRegexs()).willReturn(List.of(site + ".*"));
        reportData.setContexts(List.of(context));

        reportData.setContexts(List.of(context));

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionStats extStats =
                mock(ExtensionStats.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        // When
        dataHandler.handle(reportData);

        // Then
        assertThat(reportData.getReportObject("authdata"), is(notNullValue()));
        AuthReportData ard = (AuthReportData) reportData.getReportObject("authdata");
        assertThat(ard.isValidReport(), is(equalTo(true)));
        assertThat(ard.getSummaryItems().size(), is(equalTo(3)));

        assertThat(ard.getSummaryItems().get(0).key(), is(equalTo("auth.summary.stats")));
        assertThat(ard.getSummaryItems().get(0).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(1).key(), is(equalTo("auth.summary.session")));
        assertThat(ard.getSummaryItems().get(1).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(2).key(), is(equalTo("auth.summary.verif")));
        assertThat(ard.getSummaryItems().get(2).passed(), is(equalTo(false)));
    }

    @Test
    void shouldReportWithNoPassingStats() {
        // Given
        String site = "https://www.example.com";
        ExtensionAuthhelperReport.AuthReportDataHandler dataHandler =
                new ExtensionAuthhelperReport.AuthReportDataHandler();
        ReportData reportData = new ReportData("auth-report-test");
        Context context = mock(Context.class);

        ClientScriptBasedAuthenticationMethod authMethod =
                new ClientScriptBasedAuthenticationMethodType().createAuthenticationMethod(0);
        authMethod.setAuthCheckingStrategy(AuthCheckingStrategy.AUTO_DETECT);
        given(context.getAuthenticationMethod()).willReturn(authMethod);
        given(context.getSessionManagementMethod())
                .willReturn(
                        new AutoDetectSessionManagementMethodType()
                                .createSessionManagementMethod(0));

        given(context.getIncludeInContextRegexs()).willReturn(List.of(site + ".*"));
        reportData.setContexts(List.of(context));

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionStats extStats =
                mock(ExtensionStats.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);

        InMemoryStats stats = new InMemoryStats();
        given(extStats.getInMemoryStats()).willReturn(stats);

        stats.counterInc(site, AuthenticationHelper.AUTH_FAILURE_STATS, 2);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        // When
        dataHandler.handle(reportData);

        // Then
        assertThat(reportData.getReportObject("authdata"), is(notNullValue()));
        AuthReportData ard = (AuthReportData) reportData.getReportObject("authdata");
        assertThat(ard.isValidReport(), is(equalTo(true)));
        assertThat(ard.getSummaryItems().size(), is(equalTo(3)));

        assertThat(ard.getSummaryItems().get(0).key(), is(equalTo("auth.summary.auth")));
        assertThat(ard.getSummaryItems().get(0).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(1).key(), is(equalTo("auth.summary.session")));
        assertThat(ard.getSummaryItems().get(1).passed(), is(equalTo(false)));

        assertThat(ard.getSummaryItems().get(2).key(), is(equalTo("auth.summary.verif")));
        assertThat(ard.getSummaryItems().get(2).passed(), is(equalTo(false)));

        assertThat(
                ard.getFailureDetails(),
                contains(
                        FailureDetail.SESSION_MGMT,
                        FailureDetail.VERIF_IDENT,
                        FailureDetail.PASS_COUNT,
                        FailureDetail.NO_SUCCESSFUL_LOGINS,
                        FailureDetail.LOGIN_FAILURES,
                        FailureDetail.LOGGED_IN));
    }
}
