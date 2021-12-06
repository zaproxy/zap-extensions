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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.AbstractHostFilePluginUnitTest;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link ElmahScanRule}. */
class ElmahScanRuleUnitTest extends AbstractHostFilePluginUnitTest<ElmahScanRule> {

    private static final String URL = "/elmah.axd";
    private static final String RESPONSE_WITHOUT_EVIDENCE =
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    + "<html><head></head><body></body></html>";

    private static final String RESPONSE_WITH_EVIDENCE =
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    + "<html><head></head><body>\n"
                    + "<h1>Error Log for testing</h1>\n"
                    + "<p>Blah blah blah.</p>\n"
                    + "</body></html>";

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionAscanRules());
    }

    @Override
    protected ElmahScanRule createScanner() {
        return new ElmahScanRule();
    }

    @Override
    protected HttpMessage getHttpMessageForSendReasonableNumberOfMessages(String defaultPath)
            throws HttpMalformedHeaderException {
        return super.getHttpMessageForSendReasonableNumberOfMessages(URL);
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = ((ElmahScanRule) rule).getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(94)));
        assertThat(wasc, is(equalTo(14)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getValue())));
    }

    @ParameterizedTest
    @ValueSource(ints = {301, 403, 404, 500})
    void shouldNotAlertIfNonExistingElmahFileReturnsNon200CodeStdThreshold(int status)
            throws Exception {
        // Given
        nano.addHandler(new StatusCodeResponse("/", status));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertIfElmahFileFound() throws Exception {
        // Given
        nano.addHandler(new OkResponseWithEvidence("/"));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
    }

    @Test
    void shouldAlertIfElmahFileFoundNonRootInitialUrl() throws Exception {
        // Given
        String path = "/foo/bar/";
        nano.addHandler(new OkResponseWithoutEvidence(path));
        nano.addHandler(new OkResponseWithEvidence(URL));
        HttpMessage message = getHttpMessage(path);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
    }

    @Test
    void shouldNotAlertIfNonElmahFileFoundStdThreshold() throws Exception {
        // Given
        nano.addHandler(new OkResponseWithoutEvidence("/"));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertIfNonElmahFileFoundLowThreshold() throws Exception {
        // Given
        nano.addHandler(new OkResponseWithoutEvidence("/"));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 403})
    void shouldAlertIfBehindAuthLowThreshold(int status) throws Exception {
        // Given
        nano.addHandler(new StatusCodeResponse("/", status));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_INFO)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
    }

    private static class StatusCodeResponse extends NanoServerHandler {

        private int status;

        public StatusCodeResponse(String name, int status) {
            super(name);
            this.status = status;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return newFixedLengthResponse(
                    Response.Status.lookup(status), "text/html", RESPONSE_WITHOUT_EVIDENCE);
        }
    }

    private static class OkResponseWithEvidence extends NanoServerHandler {

        public OkResponseWithEvidence(String name) {
            super(name);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return newFixedLengthResponse(Response.Status.OK, "text/html", RESPONSE_WITH_EVIDENCE);
        }
    }

    private static class OkResponseWithoutEvidence extends NanoServerHandler {

        public OkResponseWithoutEvidence(String name) {
            super(name);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return newFixedLengthResponse(
                    Response.Status.OK, "text/html", RESPONSE_WITHOUT_EVIDENCE);
        }
    }
}
