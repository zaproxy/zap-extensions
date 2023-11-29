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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import java.util.TreeSet;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;

class SameOriginMethodExecutionScanRuleTest
        extends PassiveScannerTest<SameOriginMethodExecutionScanRule> {

    @Override
    protected SameOriginMethodExecutionScanRule createScanner() {
        return new SameOriginMethodExecutionScanRule();
    }

    private HttpMessage createMessage() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com/", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.getRequestHeader().setMethod(HttpRequestHeader.GET);
        return msg;
    }

    @Test
    void shouldRaiseAlertForHeuristicsCheck() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().getURI().setQuery("toCall=swap");
        msg.setResponseBody(
                "<html><head></head><body><script src='/api/jsonp?callback=swap'></script></body></html>");
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, DEFAULT_CONTENT_TYPE);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("toCall"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("callback=swap"));
    }

    @Test
    void shouldRaiseAlertsForSwfFiles() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        URI requestUri = msg.getRequestHeader().getURI();
        requestUri.setPath("/aweSOME.swf");
        requestUri.setQuery("jsonp=swap");
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, DEFAULT_CONTENT_TYPE);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("jsonp"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("jsonp"));
        assertThat(alertsRaised.get(0).getOtherInfo(), containsString("references an SWF file"));
    }

    @Test
    void shouldRaiseAlertsForJsonpEndpoint() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        URI requestUri = msg.getRequestHeader().getURI();
        requestUri.setPath("/awesome/jsonpendpoint");
        requestUri.setQuery("callback=swap");
        msg.getRequestHeader()
                .setHeader(HttpHeader.REFERER, "http://example.com/spa/?callback=swap");
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
        msg.setResponseBody("/**/swap({'foobar':'foo'});");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(), equalTo("http://example.com/spa/?callback=swap"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("swap"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(), containsString("This request originated from"));
    }

    @Test
    void shouldRaiseAHighConfidenceAlertForSfdHeader() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        URI requestUri = msg.getRequestHeader().getURI();
        requestUri.setPath("/awesome/jsonpendpoint");
        requestUri.setQuery("callback=swap");
        msg.getRequestHeader()
                .setHeader(HttpHeader.REFERER, "http://example.com/spa/?callback=swap");
        msg.getRequestHeader().setHeader("Sec-Fetch-Dest", "script");
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
        msg.setResponseBody("/**/swap({'foobar':'foo'});");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(), equalTo("http://example.com/spa/?callback=swap"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("swap"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(), containsString("This request originated from"));
    }

    @Test
    void shouldRaiseAlertWhenCallbackIsUrlEncodedInsideAnotherParameter() throws Exception {
        // Given
        HtmlParameter getParam =
                new HtmlParameter(HtmlParameter.Type.url, "q", "&callback=callval#");
        TreeSet<HtmlParameter> allGetParams =
                new TreeSet<>() {
                    {
                        add(getParam);
                    }
                };
        HttpMessage msg = createMessage();
        msg.setGetParams(allGetParams);
        msg.setResponseBody(
                "<html><head></head><body><script src='/api/jsonp?q=&callback=callval#&callback=callbackFunc'></script></body></html>");
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, DEFAULT_CONTENT_TYPE);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("callback"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("callback=callval"));
    }

    @Test
    void shouldNotRaiseAlertsForWhenParamValueIsEmpty() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().getURI().setQuery("toCall=");
        msg.setResponseBody(
                "<html><head></head><body><script src='/api/jsonp?callback=swap'></script></body></html>");
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, DEFAULT_CONTENT_TYPE);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertsForValidJsonResponse() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        URI requestUri = msg.getRequestHeader().getURI();
        requestUri.setPath("/awesome/validJson");
        requestUri.setQuery("callback=swap");
        msg.getRequestHeader()
                .setHeader(HttpHeader.REFERER, "http://example.com/spa/?callback=swap");
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
        msg.setResponseBody("{\"validJsonData\": \"swap({'foobar':'foo'});\"}");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertsForSfdHeaderWithValueOtherThanNullOrScript() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        URI requestUri = msg.getRequestHeader().getURI();
        requestUri.setPath("/awesome/validJson");
        requestUri.setQuery("callback=swap");
        msg.getRequestHeader()
                .setHeader(HttpHeader.REFERER, "http://example.com/spa/?callback=swap");
        msg.getRequestHeader().setHeader("Sec-Fetch-Dest", "document");
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
        msg.setResponseBody("/**/swap({'foobar':'foo'});");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }
}
