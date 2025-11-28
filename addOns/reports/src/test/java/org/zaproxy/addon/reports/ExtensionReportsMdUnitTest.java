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
package org.zaproxy.addon.reports;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Files;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionReportsMdUnitTest extends TestUtils {

    private ExtensionLoader extensionLoader;

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionReports());

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        Constant.PROGRAM_VERSION = "Dev Build";
        HttpRequestHeader.setDefaultUserAgent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0");
    }

    @AfterEach
    void cleanup() throws URISyntaxException {
        Configurator.reconfigure(getClass().getResource("/log4j2-test.properties").toURI());
    }

    @Test
    void shouldGenerateValidInsightsJsonReport() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-md");
        String fileName = "insights-traditional-md";
        File f = File.createTempFile(fileName, template.getExtension());

        // When
        File r = ReportTestUtils.generateReportWithInsights(template, f);
        String report = new String(Files.readAllBytes(r.toPath()));

        // Then
        String expected =
                """
                # Test Title

                ZAP by [Checkmarx](https://checkmarx.com/).




                ## Insights

                | Level | Reason | Site | Description | Statistic |
                | --- | --- | --- | --- | --- |
                |  |  | https://www.example.com | Insight1 desc |  |
                |  |  | https://www.example.com | Insight2 desc |  |
                |  |  |  | Insight3 desc |  |
                """;
        assertThat(report.trim(), is(equalTo(expected.trim())));
    }
}
