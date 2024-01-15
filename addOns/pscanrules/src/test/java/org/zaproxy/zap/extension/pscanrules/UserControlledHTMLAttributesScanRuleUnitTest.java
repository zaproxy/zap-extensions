/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class UserControlledHTMLAttributesScanRuleUnitTest
        extends PassiveScannerTest<UserControlledHTMLAttributesScanRule> {

    @Override
    protected UserControlledHTMLAttributesScanRule createScanner() {
        return new UserControlledHTMLAttributesScanRule();
    }

    public HttpMessage createMessage() {
        HttpMessage msg = new HttpMessage();
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        try {
            requestHeader.setURI(new URI("http://example.com/i.php", false));
        } catch (URIException | NullPointerException e) {
        }
        requestHeader.setMethod(HttpRequestHeader.GET);

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        return msg;
    }

    @Test
    void shouldNotRaiseAlertIfResponseIsNotStatusOk() {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setStatusCode(HttpStatusCode.NOT_ACCEPTABLE);
        given(passiveScanData.isPage200(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfResponseIsNotHtml() {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "application/json");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfResponseHasNoContentType() {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader(new HttpResponseHeader());
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfRequestHasNoGetParams() {
        // Given
        HttpMessage msg = createMessage();
        given(passiveScanData.isPage200(any())).willReturn(true);
        // WHen
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfRequestParamsHaveNoValues() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().setURI(new URI("http://example.com/i.php?place=&name=", false));
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfResponseContainsNoAttributes() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader()
                .setURI(new URI("http://example.com/i.php?place=here&name=fred", false));
        msg.setResponseBody("<html><H1>Title</H1></html>");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfRequestParamValuesNotUsedInAttribute() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader()
                .setURI(new URI("http://example.com/i.php?place=here&name=fred", false));
        msg.setResponseBody("<html><img src=\"x.jpg\" alt=\"Some image (x)\")></img></html>");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfRequestParamValuesNotUsedInMetaAttribute() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader()
                .setURI(new URI("http://example.com/i.php?place=here&name=fred", false));
        msg.setResponseBody(
                "<html><meta name=\"description\" content=\"UnitTest Content\"></html>");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfRequestParamValuesUsedInMetaAttribute() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader()
                .setURI(new URI("http://example.com/i.php?place=here&name=fred", false));
        msg.setResponseBody("<html><meta name=\"description\" content=\"fred\"></html>");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
    }

    @Test
    void shouldNotRaiseAlertIfRequestParamValuesNotUsedInMetaRefresh() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader()
                .setURI(new URI("http://example.com/i.php?place=here&name=fred", false));
        msg.setResponseBody(
                "<html><meta http-equiv=\"refresh\" content=\"0; url=http://example.com/\"></html>");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfRequestParamValuesUsedInMetaRefresh() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader()
                .setURI(new URI("http://example.com/i.php?place=http://example.com/", false));
        msg.setResponseBody(
                "<html><meta http-equiv=\"refresh\" content=\"0; url=http://example.com/\"></html>");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("place"));
    }

    @Test
    void shouldRaiseMultipleAlertsIfRequestParamValuesUsedInAttributes() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader()
                .setURI(
                        new URI(
                                "http://example.com/i.php?place=http://example.com/&name=fred",
                                false));
        msg.setResponseBody(
                "<html><meta http-equiv=\"refresh\" content=\"0; url=http://example.com/\"><img src=\"x.jpg\" alt=fred></img></html>");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        assertThat(alertsRaised.get(0).getParam(), equalTo("place"));
        assertThat(alertsRaised.get(1).getParam(), equalTo("name"));
    }

    @Test
    void shouldRaiseAlertIfRequestParamsValuesUsedInAttributes() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader()
                .setURI(new URI("http://example.com/i.php?place=here&name=fred", false));
        msg.setResponseBody("<html><img src=\"x.jpg\" alt=\"fred, here\")></img></html>");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        Alert alert = alerts.get(0);
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_INFO)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }
}
