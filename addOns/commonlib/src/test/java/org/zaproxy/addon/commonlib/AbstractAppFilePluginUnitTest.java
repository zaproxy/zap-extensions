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
package org.zaproxy.addon.commonlib;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link AbstractAppFilePlugin}. */
public abstract class AbstractAppFilePluginUnitTest<T extends AbstractAppFilePlugin>
        extends ActiveScannerTestUtils<AbstractAppFilePlugin> {

    private String body;

    public AbstractAppFilePluginUnitTest() {
        this.body = "<html><head></head><H>Awesome Content</H1>Some text...<html>";
    }

    public void setBody(String body) {
        this.body = body;
    }

    @Test
    public void shouldGeneratePathWithFileNameWhenOriginalPathIsNothing() throws Exception {
        // Given
        String path = "";
        Response response = newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, body);
        this.nano.addHandler(createHandler(path, response));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertEquals(1, httpMessagesSent.size());
        assertEquals(
                "/" + rule.getFilename(),
                httpMessagesSent.get(0).getRequestHeader().getURI().getPath());
    }

    @Test
    public void shouldGeneratePathWithFileNameWhenOriginalPathIsSlash() throws Exception {
        // Given
        String path = "/";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, body)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertEquals(1, httpMessagesSent.size());
        assertEquals(
                "/" + rule.getFilename(),
                httpMessagesSent.get(0).getRequestHeader().getURI().getPath());
    }

    @Test
    public void shouldGeneratePathWithFileNameWhenOriginalPathDoesNotEndInSlash() throws Exception {
        // Given
        String path = "/foo/bar";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, body)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertEquals(1, httpMessagesSent.size());
        assertEquals(
                "/foo/" + rule.getFilename(),
                httpMessagesSent.get(0).getRequestHeader().getURI().getPath());
    }

    @Test
    public void shouldGeneratePathWithFileNameWhenOriginalPathDoesEndInSlash() throws Exception {
        // Given
        String path = "/foo/bar/";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, body)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertEquals(1, httpMessagesSent.size());
        assertEquals(
                "/foo/bar/" + rule.getFilename(),
                httpMessagesSent.get(0).getRequestHeader().getURI().getPath());
    }

    @Test
    public void shouldCleanupOriginalRequestWhenMakingAppFileRequest()
            throws HttpMalformedHeaderException {
        // Given
        String path = "/";
        nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, body)));
        HttpMessage message = getHttpMessage(path);
        message.getRequestHeader().setMethod("POST");
        message.getRequestBody().setBody("foo=bar");
        message.getRequestHeader()
                .addHeader(HttpHeader.CONTENT_TYPE, "application/x-www-form-urlencoded");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        HttpMessage sentMessage = httpMessagesSent.get(0);
        assertThat(sentMessage.getRequestHeader().getMethod(), is(equalTo("GET")));
        assertThat(
                sentMessage.getRequestHeader().getHeaderValues(HttpHeader.CONTENT_TYPE),
                is(equalTo(Collections.emptyList())));
        assertThat(sentMessage.getRequestBody().length(), is(equalTo(0)));
    }

    @Test
    public void shouldAlertWhenRequestIsSuccessful() throws Exception {
        // Given
        String path = "/foo/bar/";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, body)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(1, httpMessagesSent.size());
        Alert alert = alertsRaised.get(0);
        assertEquals(Alert.RISK_MEDIUM, alert.getRisk());
        assertEquals(Alert.CONFIDENCE_MEDIUM, alert.getConfidence());
    }

    @Test
    public void shouldNotAlertWhenRequestIsNotSuccessful() throws Exception {
        // Given
        String path = "/foo/bar/";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(
                                Response.Status.INTERNAL_ERROR, NanoHTTPD.MIME_HTML, body)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotAlertWhenRequestIsNotSuccessfulEvenAtLowThreshold() throws Exception {
        // Given
        String path = "/foo/bar/";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(
                                Response.Status.INTERNAL_ERROR, NanoHTTPD.MIME_HTML, body)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.setAlertThreshold(AlertThreshold.LOW);
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotAlertWhenRequestIsUnauthorized() throws Exception {
        // Given
        String path = "/foo/bar/";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(
                                Response.Status.UNAUTHORIZED, NanoHTTPD.MIME_HTML, body)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldAlertWhenRequestIsUnauthorizedAtLowThreshold() throws Exception {
        // Given
        String path = "/foo/bar/";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(
                                Response.Status.UNAUTHORIZED, NanoHTTPD.MIME_HTML, body)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.setAlertThreshold(AlertThreshold.LOW);
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(1, httpMessagesSent.size());
        Alert alert = alertsRaised.get(0);
        assertEquals(Alert.RISK_INFO, alert.getRisk());
        assertEquals(Alert.CONFIDENCE_LOW, alert.getConfidence());
    }

    @Test
    public void shouldNotAlertWhenRequestIsForbidden() throws Exception {
        // Given
        String path = "/foo/bar/";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(
                                Response.Status.FORBIDDEN, NanoHTTPD.MIME_HTML, body)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldAlertWhenRequestIsForbiddenAtLowThreshold() throws Exception {
        // Given
        String path = "/foo/bar/";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(
                                Response.Status.UNAUTHORIZED, NanoHTTPD.MIME_HTML, body)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.setAlertThreshold(AlertThreshold.LOW);
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(1, httpMessagesSent.size());
        Alert alert = alertsRaised.get(0);
        assertEquals(Alert.RISK_INFO, alert.getRisk());
        assertEquals(Alert.CONFIDENCE_LOW, alert.getConfidence());
    }

    private static NanoServerHandler createHandler(String path, Response response) {
        return new NanoServerHandler(path) {
            @Override
            protected Response serve(IHTTPSession session) {
                return response;
            }
        };
    }
}
