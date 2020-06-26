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
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.util.TreeSet;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;

public class UserControlledOpenRedirectScanRuleUnitTest
        extends PassiveScannerTest<UserControlledOpenRedirectScanRule> {

    @Override
    protected UserControlledOpenRedirectScanRule createScanner() {
        return new UserControlledOpenRedirectScanRule();
    }

    public HttpMessage createMessage() {
        HttpMessage msg = new HttpMessage();
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        try {
            requestHeader.setURI(new URI("http://example.com/i.php", false));
        } catch (URIException | NullPointerException e) {
        }
        requestHeader.setMethod(HttpRequestHeader.GET);

        msg.setRequestHeader(requestHeader);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        return msg;
    }

    @Test
    public void shouldNotRaiseAlertIfResponseIsNotRedirect() {
        // Given
        HttpMessage msg = createMessage();
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertIfResponseIsRedirectButHasNoLocationHeader() {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertIfResponseIsRedirectHasEmptyLocationHeader() {
        // Given
        HttpMessage msg = createMessage();
        TreeSet<HtmlParameter> params = new TreeSet<HtmlParameter>();
        params.add(new HtmlParameter(HtmlParameter.Type.url, "place", "http://evil.com"));
        msg.setGetParams(params);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, "");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertIfResponseIsRedirectHasLocationHeaderNoParam() {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, "http://evil.com");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertIfResponseIsRedirectHasLocationHeaderEmptyParam() {
        // Given
        HttpMessage msg = createMessage();
        TreeSet<HtmlParameter> params = new TreeSet<HtmlParameter>();
        params.add(new HtmlParameter(HtmlParameter.Type.url, "place", ""));
        msg.setGetParams(params);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, "http://evil.com");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertIfResponseIsRedirectHasLocationHeaderIrrelevantParam() {
        // Given
        HttpMessage msg = createMessage();
        TreeSet<HtmlParameter> params = new TreeSet<HtmlParameter>();
        params.add(new HtmlParameter(HtmlParameter.Type.url, "place", "fred"));
        msg.setGetParams(params);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, "http://evil.com");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertIfResponseIsRedirectHasLocationHeaderBasedOnParam() {
        // Given
        HttpMessage msg = createMessage();
        TreeSet<HtmlParameter> params = new TreeSet<HtmlParameter>();
        params.add(new HtmlParameter(HtmlParameter.Type.url, "place", "http://evil.com"));
        msg.setGetParams(params);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, "http://evil.com");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("place"));
    }

    @Test
    public void shouldRaiseAlertIfResponseIsTempRedirectHasLocationHeaderBasedOnParam() {
        // Given
        HttpMessage msg = createMessage();
        TreeSet<HtmlParameter> params = new TreeSet<HtmlParameter>();
        params.add(new HtmlParameter(HtmlParameter.Type.url, "place", "http://evil.com"));
        msg.setGetParams(params);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.FOUND);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, "http://evil.com");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("place"));
    }

    @Test
    public void shouldRaiseAlertIfResponseIsTempRedirectHasLocationHeaderBasedOnGetParamDuringPost()
            throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().setURI(new URI("http://example.com/i.php?place=evil.com", false));
        msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        TreeSet<HtmlParameter> formParams = new TreeSet<HtmlParameter>();
        formParams.add(new HtmlParameter(HtmlParameter.Type.form, "name", "jane"));
        msg.setFormParams(formParams);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.FOUND);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, "http://evil.com");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("place"));
    }

    @Test
    public void
            shouldNotRaiseAlertIfLocationHeaderIsBasedOnGetParamButValueIsSameAsOriginDuringPost()
                    throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().setURI(new URI("http://evil.com/i.php?place=evil.com", false));
        msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        TreeSet<HtmlParameter> formParams = new TreeSet<HtmlParameter>();
        formParams.add(new HtmlParameter(HtmlParameter.Type.form, "name", "jane"));
        msg.setFormParams(formParams);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.FOUND);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, "http://evil.com");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void
            shouldNotRaiseAlertIfResponseIsRedirectHasLocationHeaderBasedOnParamButSameAsOrigin() {
        // Given
        HttpMessage msg = createMessage();
        TreeSet<HtmlParameter> params = new TreeSet<HtmlParameter>();
        params.add(new HtmlParameter(HtmlParameter.Type.url, "place", "http://example.com"));
        msg.setGetParams(params);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, "http://example.com");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void
            shouldNotRaiseAlertIfResponseIsRedirectAndParamIsOnlyMatchingProtocolOfLocationHeader() {
        // Given
        HttpMessage msg = createMessage();
        TreeSet<HtmlParameter> params = new TreeSet<HtmlParameter>();
        params.add(new HtmlParameter(HtmlParameter.Type.url, "place", "http"));
        msg.setGetParams(params);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, "http://evil.com/xyz");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertIfResponseIsRedirectHasRelativeLocationHeader() {
        // Given
        HttpMessage msg = createMessage();
        TreeSet<HtmlParameter> params = new TreeSet<HtmlParameter>();
        params.add(new HtmlParameter(HtmlParameter.Type.url, "place", "/images"));
        msg.setGetParams(params);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, "/images");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }
}
