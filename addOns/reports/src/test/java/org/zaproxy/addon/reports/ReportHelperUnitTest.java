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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.alert.AlertNode;

class ReportHelperUnitTest {

    @Test
    void shouldGetHostsForSites() throws Exception {
        // Given / When / Then
        assertThat(
                ReportHelper.getHostForSite("https://www.example.com:443"), is("www.example.com"));
        assertThat(
                ReportHelper.getHostForSite("https://www.example.com:8443/"),
                is("www.example.com"));
        assertThat(
                ReportHelper.getHostForSite("https://www.example.com:8080/path"),
                is("www.example.com"));
        assertThat(
                ReportHelper.getHostForSite("https://www.example.com/path"), is("www.example.com"));
        assertThat(
                ReportHelper.getHostForSite("http://www.example.com:8080"), is("www.example.com"));
        assertThat(
                ReportHelper.getHostForSite("http://www.example.com/path/more"),
                is("www.example.com"));
        assertThat(ReportHelper.getHostForSite("www.example.com/path/more"), is("www.example.com"));
        assertThat(
                ReportHelper.getHostForSite("http.example.com/path/more"), is("http.example.com"));
        assertThat(ReportHelper.getHostForSite(null), is(""));
    }

    @Test
    void shouldGetPortForSites() throws Exception {
        // Given / When / Then
        assertThat(ReportHelper.getPortForSite("https://www.example.com:443"), is(443));
        assertThat(ReportHelper.getPortForSite("https://www.example.com:8443"), is(8443));
        assertThat(ReportHelper.getPortForSite("https://www.example.com:8080"), is(8080));
        assertThat(ReportHelper.getPortForSite("http://www.example.com:8080"), is(8080));
        assertThat(ReportHelper.getPortForSite("https://www.example.com"), is(443));
        assertThat(ReportHelper.getPortForSite("http://www.example.com"), is(80));
        assertThat(ReportHelper.getPortForSite("www.example.com"), is(80));
        assertThat(ReportHelper.getPortForSite("https://www.example.com:bad"), is(443));
        assertThat(ReportHelper.getPortForSite("http://www.example.com:bad"), is(80));
        assertThat(ReportHelper.getPortForSite(null), is(80));
    }

    @Test
    void shouldEscapeTest() throws Exception {
        // Given / When / Then
        assertThat(ReportHelper.legacyEscapeText("Test"), is("Test"));
        assertThat(ReportHelper.legacyEscapeText(null), is(nullValue()));
        assertThat(ReportHelper.legacyEscapeText("'single quotes'"), is("'single quotes'"));
        assertThat(ReportHelper.legacyEscapeText("\"double quotes\""), is("\"double quotes\""));
    }

    @Test
    void shouldEscapeParagraph() throws Exception {
        // Given / When / Then
        assertThat(ReportHelper.legacyEscapeParagraph("Test"), is("<p>Test</p>"));
        assertThat(ReportHelper.legacyEscapeParagraph(null), is(""));
        assertThat(
                ReportHelper.legacyEscapeParagraph("'single quotes'"),
                is("<p>'single quotes'</p>"));
        assertThat(
                ReportHelper.legacyEscapeParagraph("\"double quotes\""),
                is("<p>\"double quotes\"</p>"));
        assertThat(
                ReportHelper.legacyEscapeParagraph("New\nLines\r\nTest"),
                is("<p>New</p><p>Lines</p><p>Test</p>"));
    }

    @Test
    void shouldGetAlertInstancesForSite() {
        // Given
        String example1Com = "https:///www.example-1.com";
        String example2Org = "https:///www.example-2.org";
        String example3Xyz = "https:///www.example-3.xyz";
        AlertNode rootNode = new AlertNode(-1, "Root");

        String xssAlertName = "XSS";
        // Note that the first child is always the same as the top node
        AlertNode xssNode = newAlertNode(3, xssAlertName, example1Com + "/");
        xssNode.add(newAlertNode(3, xssAlertName, example1Com + "/2"));
        xssNode.add(newAlertNode(3, xssAlertName, example1Com + "/3"));
        xssNode.add(newAlertNode(3, xssAlertName, example2Org + "/3"));
        rootNode.add(xssNode);

        String sqlAlertName = "SQLi";
        AlertNode sql3Node = newAlertNode(3, sqlAlertName, example2Org + "/1");
        sql3Node.add(newAlertNode(3, sqlAlertName, example2Org + "/1"));
        sql3Node.add(newAlertNode(3, sqlAlertName, example3Xyz + "/"));
        rootNode.add(sql3Node);

        // Level 2 risk instead of 3 above
        AlertNode sql2Node = newAlertNode(2, sqlAlertName, example3Xyz + "/1");
        sql2Node.add(newAlertNode(2, sqlAlertName, example3Xyz + "/1"));
        rootNode.add(sql2Node);

        // When
        List<Alert> ex1xssAlerts =
                ReportHelper.getAlertInstancesForSite(rootNode, example1Com, xssAlertName, 3);
        List<Alert> ex2xssAlerts =
                ReportHelper.getAlertInstancesForSite(rootNode, example2Org, xssAlertName, 3);
        List<Alert> ex3xssAlerts =
                ReportHelper.getAlertInstancesForSite(rootNode, example3Xyz, xssAlertName, 3);

        List<Alert> ex1sql3Alerts =
                ReportHelper.getAlertInstancesForSite(rootNode, example1Com, sqlAlertName, 3);
        List<Alert> ex2sql3Alerts =
                ReportHelper.getAlertInstancesForSite(rootNode, example2Org, sqlAlertName, 3);
        List<Alert> ex3sql3Alerts =
                ReportHelper.getAlertInstancesForSite(rootNode, example3Xyz, sqlAlertName, 3);

        List<Alert> ex1sql2Alerts =
                ReportHelper.getAlertInstancesForSite(rootNode, example1Com, sqlAlertName, 2);
        List<Alert> ex2sql2Alerts =
                ReportHelper.getAlertInstancesForSite(rootNode, example2Org, sqlAlertName, 2);
        List<Alert> ex3sql2Alerts =
                ReportHelper.getAlertInstancesForSite(rootNode, example3Xyz, sqlAlertName, 2);

        // Then
        assertThat(ex1xssAlerts.size(), is(2));
        assertThat(ex2xssAlerts.size(), is(1));
        assertThat(ex3xssAlerts.size(), is(0));

        assertThat(ex1sql3Alerts.size(), is(0));
        assertThat(ex2sql3Alerts.size(), is(1));
        assertThat(ex3sql3Alerts.size(), is(1));

        assertThat(ex1sql2Alerts.size(), is(0));
        assertThat(ex2sql2Alerts.size(), is(0));
        assertThat(ex3sql2Alerts.size(), is(1));
    }

    AlertNode newAlertNode(int risk, String name, String url) {
        AlertNode node = new AlertNode(risk, name);
        Alert alert = new Alert(1);
        alert.setName(name);
        alert.setUri(url);
        alert.setRisk(risk);
        node.setUserObject(alert);
        return node;
    }
}
