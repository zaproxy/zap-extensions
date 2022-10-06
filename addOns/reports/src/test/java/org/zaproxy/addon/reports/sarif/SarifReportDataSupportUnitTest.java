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
package org.zaproxy.addon.reports.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.zaproxy.addon.reports.sarif.TestAlertBuilder.newAlertBuilder;
import static org.zaproxy.addon.reports.sarif.TestAlertNodeBuilder.newAlertNodeBuilder;

import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.zap.extension.alert.AlertNode;

class SarifReportDataSupportUnitTest {

    private ReportData reportData;

    @BeforeEach
    void beforeEach() {}

    @ParameterizedTest()
    @CsvSource({
        "Dev Build,0.0.0-Dev Build",
        "dev build, 0.0.0-dev build",
        "something-else,0.0.0-something-else",
        ",0.0.0-null",
        "1.0,1.0",
        "2.1,2.1",
        "'',0.0.0-",
        "1,1",
        "2.11.1,2.11.1"
    })
    void resolveSemanticZapVersion(String zapVersion, String expectedSemanticVersion) {
        /* prepare */
        reportData = new ReportData();
        SarifReportDataSupport toTest = new SarifReportDataSupport(reportData);

        /* execute */
        String semanticVersion = toTest.ensureSemanticVersion(zapVersion);

        /* test */
        assertEquals(expectedSemanticVersion, semanticVersion);
    }

    @Test
    void threeAlertsTwoDifferentResultInTwoSarifRules() {
        /* prepare */
        reportData = new ReportData();
        AlertNode rootNode = new AlertNode(0, "root");
        reportData.setAlertTreeRootNode(rootNode);

        AlertNode plugin1NodeA =
                newAlertNodeBuilder(
                                newAlertBuilder()
                                        .setPluginId(1)
                                        .setName("Name1")
                                        .setUriString("https://example.com/test1")
                                        .build())
                        .build();

        AlertNode plugin1NodeB =
                newAlertNodeBuilder(
                                newAlertBuilder()
                                        .setPluginId(1)
                                        .setName("Name1")
                                        .setUriString("https://example.com/test2")
                                        .build())
                        .build();

        AlertNode plugin2Node =
                newAlertNodeBuilder(
                                newAlertBuilder()
                                        .setPluginId(2)
                                        .setName("Name2")
                                        .setUriString("https://example.com/test3")
                                        .build())
                        .build();

        rootNode.add(plugin1NodeA);
        rootNode.add(plugin1NodeB);
        rootNode.add(plugin2Node);

        reportData.setSites(Arrays.asList("https://example.com"));
        SarifReportDataSupport toTest = new SarifReportDataSupport(reportData);

        /* execute */
        Collection<SarifRule> rules = toTest.getRules();

        /* test */
        assertEquals(2, rules.size());
        Iterator<SarifRule> it = rules.iterator();
        SarifRule rule1 = it.next();
        SarifRule rule2 = it.next();

        assertEquals("Name1", rule1.getName());
        assertEquals("1", rule1.getId());

        assertEquals("Name2", rule2.getName());
        assertEquals("2", rule2.getId());
    }

    @Test
    void ruleHasFullDescription() {
        /* prepare */
        reportData = new ReportData();
        AlertNode rootNode = new AlertNode(0, "root");
        reportData.setAlertTreeRootNode(rootNode);

        AlertNode plugin1NodeA =
                newAlertNodeBuilder(
                                newAlertBuilder()
                                        .setDescription("this is a description")
                                        .setUriString("https://example.com/test1")
                                        .build())
                        .build();

        rootNode.add(plugin1NodeA);

        reportData.setSites(Arrays.asList("https://example.com"));
        SarifReportDataSupport toTest = new SarifReportDataSupport(reportData);

        /* execute */
        Collection<SarifRule> rules = toTest.getRules();

        /* test */
        assertEquals(1, rules.size());
        Iterator<SarifRule> it = rules.iterator();
        SarifRule rule1 = it.next();
        assertEquals("this is a description", rule1.getFullDescription());
    }
}
