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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;

public class UserControlledJavascriptEventScanRuleUnitTest
        extends PassiveScannerTest<UserControlledJavascriptEventScanRule> {

    @Override
    protected UserControlledJavascriptEventScanRule createScanner() {
        return new UserControlledJavascriptEventScanRule();
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
    public void shouldNotRaiseAlertIfResponseIsNotStatusOk() {
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
    public void shouldNotRaiseAlertIfResponseIsNotHtml() {
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
    public void shouldNotRaiseAlertIfResponsehasNoContentType() {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, ""); // Removed when value set empty
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertIfRequestHasNoGetParams() {
        // Given
        HttpMessage msg = createMessage();
        given(passiveScanData.isPage200(any())).willReturn(true);
        // WHen
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertIfRequestParamsHaveNoValues() throws Exception {
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
    public void shouldNotRaiseAlertIfRequestParamValuesNotUsedInJsEvent() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader()
                .setURI(new URI("http://example.com/i.php?place=here&name=fred", false));
        msg.setResponseBody("<html><img src=\"x.jpg\" onerror=alert(\"Error\")></img></html>");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertIfResponseHasUnknownJsEvent() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader()
                .setURI(new URI("http://example.com/i.php?place=here&name=fred", false));
        msg.setResponseBody("<html><img src=\"x.jpg\" onblah=fred></img></html>");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertIfRequestParamValuesUsedInJsEvent() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader()
                .setURI(new URI("http://example.com/i.php?place=here&name=fred", false));
        msg.setResponseBody("<html><img src=\"x.jpg\" onerror=fred></img></html>");
        given(passiveScanData.isPage200(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
    }
}
