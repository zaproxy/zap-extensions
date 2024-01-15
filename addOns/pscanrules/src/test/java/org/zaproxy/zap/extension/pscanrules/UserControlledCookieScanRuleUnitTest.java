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

import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class UserControlledCookieScanRuleUnitTest
        extends PassiveScannerTest<UserControlledCookieScanRule> {

    @Override
    protected UserControlledCookieScanRule createScanner() {
        return new UserControlledCookieScanRule();
    }

    public HttpMessage createMessage() {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        try {
            requestHeader.setURI(new URI("http://example.com/i.php", false));
        } catch (URIException | NullPointerException e) {
        }
        requestHeader.setMethod(HttpRequestHeader.GET);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        return msg;
    }

    @Test
    void shouldNotRaiseAlertIfResponseDoesntSetCookie() {
        // Given
        HttpMessage msg = createMessage();
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfRequestHasNoGetParams() {
        // Given
        HttpMessage msg = createMessage();
        // WHen
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfResponseHasCookiesButRequestHasNoParams() {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "Set-Cookie: aCookie=aValue; Secure");
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
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "Set-Cookie: aCookie=aValue; Secure");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfCookieHasNoValue() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().setURI(new URI("http://example.com/i.php?place=&name=fred", false));
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "Set-Cookie: aCookie=\"\"; Secure");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfCookieIsEmpty() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().setURI(new URI("http://example.com/i.php?place=&name=fred", false));
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfRequestParamsAppearAsCookieValue() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().setURI(new URI("http://example.com/i.php?place=&name=fred", false));
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "Set-Cookie: aCookie=fred; Secure");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
    }

    @Test
    void shouldNotRaiseAlertIfRequestParamsAppearWithinCookieValue() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().setURI(new URI("http://example.com/i.php?place=&name=fred", false));
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "Set-Cookie: aCookie=freddy; Secure");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfCookieBasedOnGetParamDuringPost() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().setURI(new URI("http://example.com/i.php?place=evil", false));
        msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        TreeSet<HtmlParameter> formParams = new TreeSet<>();
        formParams.add(new HtmlParameter(HtmlParameter.Type.form, "name", "jane"));
        msg.setFormParams(formParams);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.FOUND);
        msg.getResponseHeader()
                .setHeader(HttpHeader.SET_COOKIE, "Set-Cookie: aCookie=evil; Secure");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("place"));
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
