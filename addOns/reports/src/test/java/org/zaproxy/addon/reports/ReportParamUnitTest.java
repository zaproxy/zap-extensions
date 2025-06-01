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
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Locale;
import org.apache.commons.configuration.XMLConfiguration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.utils.I18N;

class ReportParamUnitTest {

    private ReportParam reportParam;

    @BeforeAll
    static void initModel() {
        Constant.messages = new I18N(Locale.ENGLISH);
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
    }

    @BeforeEach
    void init() {
        reportParam = new ReportParam();
    }

    @Test
    void shouldLoadDefaultParams() {
        // Given
        XMLConfiguration config = new XMLConfiguration();

        // When
        reportParam.load(config);

        // Then
        assertThat(reportParam.getTitle(), is(equalTo("!reports.report.title!")));
        assertThat(reportParam.getDescription(), is(equalTo("")));
        assertThat(reportParam.getTemplate(), is(equalTo("risk-confidence-html")));
        assertThat(
                reportParam.getReportNamePattern(), is(equalTo(ReportParam.DEFAULT_NAME_PATTERN)));
        assertThat(reportParam.getReportDirectory(), is(equalTo(System.getProperty("user.home"))));
        assertThat(
                reportParam.getTemplateDirectory(),
                is(equalTo(Constant.getZapHome() + "/reports/")));
        assertThat(reportParam.isDisplayReport(), is(equalTo(true)));
    }

    @Test
    void shouldLoadExpectedParams() throws IOException {
        // Given
        File tempDir = Files.createTempDirectory("Test").toFile();
        XMLConfiguration config = new XMLConfiguration();
        config.addProperty("reports.title", "Report title");
        config.addProperty("reports.description", "Report desc");
        config.addProperty("reports.template", "Report template");
        config.addProperty("reports.reportPattern", "Name pattern");
        config.addProperty("reports.reportDir", "/test/123/");
        config.addProperty("reports.templateDir", tempDir.getAbsolutePath());
        config.addProperty("reports.display", "false");

        // When
        reportParam.load(config);

        // Then
        assertThat(reportParam.getTitle(), is(equalTo("Report title")));
        assertThat(reportParam.getDescription(), is(equalTo("Report desc")));
        assertThat(reportParam.getTemplate(), is(equalTo("Report template")));
        assertThat(reportParam.getReportNamePattern(), is(equalTo("Name pattern")));
        assertThat(reportParam.getReportDirectory(), is(equalTo("/test/123/")));
        assertThat(reportParam.getTemplateDirectory(), is(equalTo(tempDir.getAbsolutePath())));
        assertThat(reportParam.isDisplayReport(), is(equalTo(false)));
    }

    @Test
    void shouldSetSpecifiedParams() {
        // Given
        XMLConfiguration config = new XMLConfiguration();

        // When
        reportParam.load(config);
        reportParam.setTitle("Report title");
        reportParam.setDescription("Report desc");
        reportParam.setTemplate("Report template");
        reportParam.setReportNamePattern("Name pattern");
        reportParam.setReportDirectory("/test/123/");
        reportParam.setTemplateDirectory("/test/123/");
        reportParam.setDisplayReport(false);

        // Then
        assertThat(config.getString("reports.title"), is(equalTo("Report title")));
        assertThat(config.getString("reports.description"), is(equalTo("Report desc")));
        assertThat(config.getString("reports.template"), is(equalTo("Report template")));
        assertThat(config.getString("reports.reportPattern"), is(equalTo("Name pattern")));
        assertThat(config.getString("reports.reportDir"), is(equalTo("/test/123/")));
        assertThat(config.getString("reports.templateDir"), is(equalTo("/test/123/")));
        assertThat(config.getBoolean("reports.display"), is(equalTo(false)));
    }
}
