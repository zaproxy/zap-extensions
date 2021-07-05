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

import org.junit.jupiter.api.Test;

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
}
