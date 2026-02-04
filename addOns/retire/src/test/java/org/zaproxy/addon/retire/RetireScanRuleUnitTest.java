/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.retire;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.addon.retire.model.Repo;

class RetireScanRuleUnitTest extends PassiveScannerTest<RetireScanRule> {

    @Override
    protected RetireScanRule createScanner() {
        try {
            Repo testRepo = new Repo("/org/zaproxy/addon/retire/testrepository.json");
            return new RetireScanRule(testRepo);
        } catch (IOException e) {
            // Nothing to do
        }
        return new RetireScanRule(null);
    }

    @Test
    void shouldIgnoreNon200OkMessages() {
        // Given
        HttpMessage msg =
                createMessage("http://example.com/ajax/libs/angularjs/1.2.19/angular.min.js", null);
        msg.getResponseHeader().setStatusCode(403);
        given(passiveScanData.isPage200(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @ParameterizedTest
    @CsvSource({
        "text/css, style.css",
        "text/css, style.scss",
        "'', style.css",
        "text/css, ''",
        "text/css, styles",
        "video/mp4, foo.mp4",
        "image/gif, ''",
        "image/gif, foo.gif",
        "'', image/gif"
    })
    void shouldIgnoreIrrelevantResponseContentTypes(String contentType, String file) {
        // Given
        HttpMessage msg = createMessage("https://www.example.com/assets/" + file, null);
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldRaiseAlertOnVulnerableUrl() {
        // Given
        HttpMessage msg =
                createMessage("http://example.com/ajax/libs/angularjs/1.2.19/angular.min.js", null);
        msg.getResponseHeader().setHeader(HttpFieldsNames.CONTENT_TYPE, "text/javascript");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_LOW)));
        assertEquals("/1.2.19/angular.min.js", alertsRaised.get(0).getEvidence());
        assertRefs(alertsRaised.get(0));
    }

    @Test
    void shouldNotRaiseAlertOnUrlWithNonVersionIdentifier() {
        // Given
        HttpMessage msg =
                createMessage("http://example.com/ajax/libs/000-000-0000-00/lodash.min.js", null);
        msg.getResponseHeader().setHeader(HttpFieldsNames.CONTENT_TYPE, "text/javascript");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"jquery-3.1.1.min.js", "jquery-3_1_1.min.js", "jquery-3-1-1.min.js"})
    void shouldRaiseAlertOnVulnerableFilename(String fileName) {
        // Given
        HttpMessage msg = createMessage("http://example.com/CommonElements/js/" + fileName, null);
        msg.getResponseHeader().setHeader(HttpFieldsNames.CONTENT_TYPE, "text/javascript");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertEquals(fileName, alertsRaised.get(0).getEvidence());
        assertRefs(alertsRaised.get(0));
    }

    @Test
    void shouldNotRaiseAlertOnFilenameWithNonVersionIdentifier() {
        // Given
        String fileName = "npm.moment.7a06f256.js";
        HttpMessage msg = createMessage("http://example.com/CommonElements/js/" + fileName, null);
        msg.getResponseHeader().setHeader(HttpFieldsNames.CONTENT_TYPE, "text/javascript");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldRaiseAlertOnVulnerableContent() {
        // Given
        String content =
                """
                /*!
                 * Bootstrap v3.3.7 (http://getbootstrap.com)
                 * Copyright 2011-2016 Twitter, Inc.
                 * Licensed under the MIT license
                 */""";
        HttpMessage msg = createMessage("http://example.com/angular.min.js", content);
        msg.getResponseHeader().setHeader(HttpFieldsNames.CONTENT_TYPE, "text/javascript");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertEquals("* Bootstrap v3.3.7", alertsRaised.get(0).getEvidence());
        assertRefs(alertsRaised.get(0));
        assertEquals(7, alertsRaised.get(0).getTags().size());
    }

    @Test
    void shouldNotRaiseAlertOnNonVulnerableContent() {
        // Given
        String content =
                """
                /*!
                 * Bootstrap v3.4.0 (http://getbootstrap.com)
                 * Copyright 2011-2016 Twitter, Inc.
                 * Licensed under the MIT license
                 */""";
        HttpMessage msg = createMessage("http://example.com/angular.min.js", content);
        msg.getResponseHeader().setHeader(HttpFieldsNames.CONTENT_TYPE, "text/javascript");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldRaiseAlertOnHashOfVulnerableContent() {
        // Given
        String content =
                """
                /*!
                 * Hash test content v0.0.1
                 * Copyright 2011-2016 Null, Inc.
                 * Licensed under the MIT license
                 */""";
        HttpMessage msg = createMessage("http://example.com/hash.js", content);
        msg.getResponseHeader().setHeader(HttpFieldsNames.CONTENT_TYPE, "text/javascript");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_LOW)));
        assertEquals(
                """
                The identified library hash-test-entry, version 0.0.1 is vulnerable.
                CVE-XXXX-XXX2
                CVE-XXXX-XXX1
                CVE-XXXX-XXX0
                The library matched the known vulnerable hash e19cea51d7542303f6e8949a0ae27dd3509ea566.
                http://example.com/hash-test-entry
                http://example.com/hash-test-entry2
                """,
                alertsRaised.get(0).getOtherInfo());
        assertRefs(alertsRaised.get(0));
    }

    @Test
    void shouldNotRaiseAlertOnDontCheckUrl() {
        // Given
        HttpMessage msg = createMessage("https://www.google-analytics.com/ga.js", null);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        int cweId = rule.getExampleAlerts().get(0).getCweId();
        // Then
        assertThat(cweId, is(equalTo(1395)));
        assertThat(tags.size(), is(equalTo(5)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        Alert example = alerts.get(0);
        assertThat(example.getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(
                example.getDescription(),
                is(equalTo("The identified library appears to be vulnerable.")));
        assertThat(example.getEvidence(), is(equalTo("13.3.7")));
        assertThat(
                example.getOtherInfo(),
                is(
                        equalTo(
                                "The identified library ExampleLibrary.js, version 13.3.7 is vulnerable.\n")));
        assertRefs(example);
    }

    private static void assertRefs(Alert alert) {
        assertThat(
                alert.getReference(),
                is(
                        equalTo(
                                "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/")));
    }

    private static HttpMessage createMessage(String url, String body) {
        if (url == null) {
            url = "http://example.com/";
        }
        if (body == null) {
            body = "<html><head></head><body><H1>Some Heading</H1></body></html>";
        }
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        try {
            requestHeader.setURI(new URI(url, false));
        } catch (URIException | NullPointerException e) {
            // Nothing to do
        }
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        try {
            msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
        } catch (HttpMalformedHeaderException e) {
            // Nothing to do
        }
        msg.getResponseHeader().setHeader(HttpFieldsNames.CONTENT_TYPE, "text/html");
        msg.setResponseBody(body);

        return msg;
    }

    @Test
    void shouldUseSameRepoInstance() {
        RetireScanRule scanRule = createScanner();

        scanRule.setConfig(mock(HierarchicalConfiguration.class));
        RetireScanRule copiedScanRule = (RetireScanRule) scanRule.copy();

        assertSame(scanRule.getRepo(), copiedScanRule.getRepo());
    }

    @Test
    void shouldShareRepoInCopy() throws IOException {
        // Given
        Repo testRepo = new Repo("/org/zaproxy/addon/retire/testrepository.json");
        RetireScanRule scanRule = new RetireScanRule(testRepo);
        scanRule.setConfig(mock(HierarchicalConfiguration.class));

        // When
        RetireScanRule copiedScanRule = (RetireScanRule) scanRule.copy();

        // Then
        assertSame(testRepo, copiedScanRule.getRepo());
        assertSame(scanRule.getRepo(), copiedScanRule.getRepo());
    }
}
