/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.BDDMockito.given;

import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;

class FullPathDisclosureScanRuleUnitTest extends PassiveScannerTest<FullPathDisclosureScanRule> {

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(5)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_ERRH_01_ERR.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_ERRH_01_ERR.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_ERRH_01_ERR.getValue())));
    }

    @Test
    void shouldNotRaiseAnyAlertsWhenResponseIsSuccess() throws URIException {
        // Given
        HttpMessage msg = createMessage("/home/servers/", HttpStatusCode.OK);
        given(passiveScanData.isSuccess(msg)).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertsWhenHtmlTagsLookLikeUnixPath() throws URIException {
        // Given
        String testBody =
                "\n"
                        + "<!DOCTYPE html>\n"
                        + "<html lang=\"en\">\n"
                        + "<head>\n"
                        + "<meta charset=\"utf-8\">\n"
                        + "<title>Error</title>\n"
                        + "</head>\n"
                        + "<body>\n"
                        + "<pre>Cannot GET /</pre>\n"
                        + "</body>\n"
                        + "</html>\n";
        HttpMessage message = createMessage(testBody, HttpStatusCode.NOT_FOUND);
        given(passiveScanData.isSuccess(message)).willReturn(false);
        // When
        scanHttpResponseReceive(message);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldRaiseLowRiskAlertWhenWindowsFullPathIsDisclosed() throws URIException {
        // Given
        String testBody =
                "<pre>Error: Failed to lookup view &quot;no&quot; in views directory &quot;D:\\Progra~1\\testingServer/public&quot;<br>";
        HttpMessage msg = createMessage(testBody, HttpStatusCode.NOT_FOUND);
        given(passiveScanData.isSuccess(msg)).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(Alert.RISK_LOW, alertsRaised.get(0).getRisk());
    }

    @Test
    void shouldRaiseLowRiskAlertWhenUnixBasedFullPathIsDisclosed() throws URIException {
        // Given
        String testBody =
                "<pre>Error: Failed to lookup view &quot;no&quot; in views directory &quot;/home/Software/testingServer/&quot;<br>";
        HttpMessage msg = createMessage(testBody, HttpStatusCode.NOT_FOUND);
        given(passiveScanData.isSuccess(msg)).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(Alert.RISK_LOW, alertsRaised.get(0).getRisk());
    }

    @Test
    void shouldNotAlertOnPlainPathUrl() throws URIException {
        // Given
        String testBody =
                "<html><body><a href='/student/dashboard/en-us.'>Dashboard</a></body></html>";
        HttpMessage msg = createMessage(testBody, HttpStatusCode.NOT_FOUND);
        given(passiveScanData.isSuccess(msg)).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @CsvSource(
            value = {
                "c:\\Program Files\\",
                "f:\\Users\\",
                "c:\\Windows\\",
                "c:\\ProgramData\\",
                "c:\\Progra~1\\",
                "/bin/",
                "/usr/",
                "/mnt/",
                "/proc/",
                "/sbin/",
                "/dev/",
                "/lib/",
                "/tmp/",
                "/opt/",
                "/home/",
                "/var/",
                "/root/",
                "/etc/",
                "/Applications/",
                "/Volumes/",
                "/System/",
                "/Developer/",
                "/Library/",
                "/Users/"
            })
    void shouldRaiseAlertWhenDefaultPathIsExposed(String defaultPath) throws URIException {
        // Given
        HttpMessage msg =
                createMessage("Error : Cant find" + defaultPath, HttpStatusCode.NOT_FOUND);
        given(passiveScanData.isSuccess(msg)).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(defaultPath, alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldHaveExpectedExampleAlerts() {
        // Given / When
        List<Alert> examples = rule.getExampleAlerts();
        // Then
        assertThat(examples.size(), is(equalTo(1)));
        Alert alert = examples.get(0);
        assertThat(alert.getName(), is(equalTo("Full Path Disclosure")));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_LOW)));
        assertThat(alert.getAlertRef(), is(equalTo("110009")));
        assertThat(alert.getCweId(), is(equalTo(209)));
    }

    @Override
    protected FullPathDisclosureScanRule createScanner() {
        return new FullPathDisclosureScanRule();
    }

    private static HttpMessage createMessage(String body, Integer status) throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.getResponseHeader().setStatusCode(status);
        msg.setResponseBody(body);
        return msg;
    }
}
