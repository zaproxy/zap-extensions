/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
import static org.hamcrest.Matchers.is;

import java.io.IOException;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;

public class BigRedirectsScanRuleUnitTest extends PassiveScannerTest<BigRedirectsScanRule> {
    private static final String URI = "http://example.com";
    private static final int ALLOWABLE_BODY_SIZE = URI.length() + 300;

    private HttpMessage msg;

    @BeforeEach
    public void createHttpMessage() throws IOException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI(URI, false));

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
    }

    @Override
    protected BigRedirectsScanRule createScanner() {
        return new BigRedirectsScanRule();
    }

    @Test
    public void givenRedirectWithSmallBodyThenItRaisesNoAlert() {
        // Given
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, URI);
        msg.setResponseBody(new byte[ALLOWABLE_BODY_SIZE]);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void givenRedirectHeadersWithLargeBodyThenAlertRaised() {
        // Given
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, URI);
        msg.setResponseBody(new byte[ALLOWABLE_BODY_SIZE + 1]);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertBigRedirectAlertAttributes(alertsRaised.get(0));
    }

    @Test
    public void givenNotModifiedStatusCodeWithLargeBodyThenNoAlertRaised() {
        // Given
        msg.getResponseHeader().setStatusCode(HttpStatusCode.NOT_MODIFIED);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, URI);
        msg.setResponseBody(new byte[ALLOWABLE_BODY_SIZE + 1]);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void givenNotFoundStatusCodeWithLargeBodyThenNoAlertRaised() {
        // Given
        msg.getResponseHeader().setStatusCode(HttpStatusCode.NOT_FOUND);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, URI);
        msg.setResponseBody(new byte[ALLOWABLE_BODY_SIZE + 1]);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void givenRedirectStatusCodeWithoutLocationHeaderThenNoAlertRaised() {
        // Given
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.setResponseBody(new byte[ALLOWABLE_BODY_SIZE + 1]);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    private static void assertBigRedirectAlertAttributes(Alert alert) {
        assertThat(alert.getRisk(), is(Alert.RISK_LOW));
        assertThat(alert.getConfidence(), is(Alert.CONFIDENCE_MEDIUM));
        assertThat(alert.getName(), is(getLocalisedString("name")));
        assertThat(alert.getDescription(), is(getLocalisedString("desc")));
        assertThat(alert.getSolution(), is(getLocalisedString("soln")));
        assertThat(alert.getReference(), is(getLocalisedString("refs")));
        assertThat(alert.getOtherInfo(), is(getExpectedExtraInfo()));
        assertThat(alert.getCweId(), is(201));
        assertThat(alert.getWascId(), is(13));
        assertThat(alert.getUri(), is(URI));
    }

    private static String getExpectedExtraInfo() {
        int bodySize = ALLOWABLE_BODY_SIZE;
        return getLocalisedString("extrainfo", URI.length(), URI, bodySize, bodySize + 1);
    }

    private static String getLocalisedString(String key, Object... params) {
        return Constant.messages.getString("pscanbeta.bigredirects." + key, params);
    }
}
