/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.testutils.NanoServerHandler;

class SourceCodeDisclosureFileInclusionScanRuleUnitTest
        extends ActiveScannerTest<SourceCodeDisclosureFileInclusionScanRule> {

    private static final String DEFAULT_RESPONSE_STRING = "<html><body></body></html>";

    @Override
    protected SourceCodeDisclosureFileInclusionScanRule createScanner() {
        return new SourceCodeDisclosureFileInclusionScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(541)));
        assertThat(wasc, is(equalTo(33)));
        assertThat(tags.size(), is(equalTo(5)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2025_A02_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2025_A02_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2025_A02_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        // Given
        Vulnerability vuln = Vulnerabilities.getDefault().get("wasc_33");
        // When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        Alert alert = alerts.get(0);

        Map<String, String> tags = alert.getTags();
        assertThat(tags.size(), is(equalTo(6)));
        assertThat(tags, hasKey("CWE-541"));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2025_A02_SEC_MISCONFIG.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()));
        assertThat(tags, hasKey(PolicyTag.QA_FULL.getTag()));
        assertThat(tags, hasKey(PolicyTag.PENTEST.getTag()));

        assertThat(alert.getDescription(), is(equalTo(vuln.getDescription())));
        assertThat(alert.getSolution(), is(equalTo(vuln.getSolution())));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldSkipUrlParams() {
        // Given
        HttpMessage msg = createMessage("/param/test/");
        rule.init(msg, parent);
        scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_URLPATH);
        // When
        rule.scan();
        // Then
        assertThat(countMessagesSent, is(equalTo(0)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "/"})
    void shouldSkipIfNoOrEmptyPath(String path) {
        // Given
        HttpMessage msg = createMessage(path);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(countMessagesSent, is(equalTo(0)));
    }

    @Test
    void shouldNotContinueIfRandomBodyIsEmpty() throws IOException {
        // Given
        String path = "/shouldNotContinueIfRandomBodyIsEmpty";
        nano.addHandler(new FiHandler(path, Response.Status.OK, ""));
        HttpMessage msg = getHttpMessage(path + "?inc=bar");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
        assertThat(httpMessagesSent, is(not(empty())));
    }

    @Test
    void shouldNotContinueIfRandomBodyIsTooSimilar() throws IOException {
        // Given
        String path = "/shouldNotContinueIfRandomBodyIsTooSimilar";
        nano.addHandler(new FiHandler(path, Response.Status.OK, DEFAULT_RESPONSE_STRING));
        HttpMessage msg = this.getHttpMessage("GET", path + "?inc=bar", DEFAULT_RESPONSE_STRING);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
        assertThat(httpMessagesSent, is(not(empty())));
    }

    @ParameterizedTest
    @ValueSource(strings = {"php", "jsp", "war", "ear", "rar"})
    void shouldAlertWhenConditionsRightAndExtensionMatchesContent(String ext) throws IOException {
        // Given
        String path = "/shouldAlertWhenConditionsRightAndExtensionMatchesContent." + ext;
        nano.addHandler(new FiHandler(path, Response.Status.OK, "different"));
        HttpMessage msg = this.getHttpMessage("GET", path + "?inc=bar", DEFAULT_RESPONSE_STRING);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(httpMessagesSent, is(not(empty())));
    }

    @ParameterizedTest
    @ValueSource(ints = {403, 404, 405, 500, 503})
    void shouldNotContinueIfOriginalMessageWasAnEroor(int status) throws IOException {
        // Given
        String path = "/shouldNotContinueIfOriginalMessageWasAnEroor.";
        nano.addHandler(new FiHandler(path, Response.Status.OK, "different"));
        HttpMessage msg = this.getHttpMessage("GET", path + "?inc=bar", DEFAULT_RESPONSE_STRING);
        msg.getResponseHeader().setStatusCode(status);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
        assertThat(httpMessagesSent, is(empty()));
    }

    @Test
    void shouldNotAlertWhenNoExtensionAndBodyLacksSourcePatterns() throws IOException {
        // Given: extensionless path, different body, but no JSP/PHP/Java markers
        String path = "/shouldNotAlertWhenNoExtensionAndBodyLacksSourcePatterns";
        nano.addHandler(new FiHandler(path, Response.Status.OK, "different"));
        HttpMessage msg = this.getHttpMessage("GET", path + "?inc=bar", DEFAULT_RESPONSE_STRING);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
        assertThat(httpMessagesSent, is(not(empty())));
    }

    @Test
    void shouldNotAlertOnExtensionlessReflectingEchoPage() throws IOException {
        // Given: page HTML-escapes and echoes the query param (zaproxy/zaproxy#9514)
        String path = "/echo";
        nano.addHandler(new EchoHandler(path));
        HttpMessage msg =
                this.getHttpMessage(
                        "GET", path + "?q=hello", "<html><body><p>echo: hello</p></body></html>");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldAlertWhenNoExtensionButBodyMatchesPhpSource() throws IOException {
        // Given: still alert when extensionless response looks like PHP source
        String path = "/shouldAlertWhenNoExtensionButBodyMatchesPhpSource";
        nano.addHandler(new FiHandler(path, Response.Status.OK, "different", "<?php echo 1;"));
        HttpMessage msg = this.getHttpMessage("GET", path + "?inc=bar", DEFAULT_RESPONSE_STRING);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldNotAlertWhenConditionsRightAndDisclosureResponseEmpty() throws IOException {
        // Given
        String path = "/empty";
        nano.addHandler(new FiHandler(path, Response.Status.OK, "different"));
        HttpMessage msg = this.getHttpMessage("GET", path + "?inc=bar", DEFAULT_RESPONSE_STRING);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent.size(), is(equalTo(14)));
        assertThat(alertsRaised, hasSize(0));
    }

    private static HttpMessage createMessage(String path) {
        try {

            HttpMessage msg = new HttpMessage(new URI("https://example.com" + path, true));
            msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
            return msg;
        } catch (URIException | HttpMalformedHeaderException | NullPointerException e) {
            // Ignore
        }
        return null;
    }

    private static class FiHandler extends NanoServerHandler {
        private final Response.IStatus status;
        private final String randBody;
        private final String disclosureBody;

        public FiHandler(String path, Response.IStatus status, String randBody) {
            this(path, status, randBody, "something");
        }

        public FiHandler(
                String path, Response.IStatus status, String randBody, String disclosureBody) {
            super(path);
            this.status = status;
            this.randBody = randBody;
            this.disclosureBody = disclosureBody;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String pValue = getFirstParamValue(session, "inc");

            if (pValue.length() == 38) {
                return newFixedLengthResponse(status, NanoHTTPD.MIME_HTML, randBody);
            }

            String uri = session.getUri();
            uri = uri.replace(session.getQueryParameterString(), "");
            if (uri.endsWith(".php")) {
                return newFixedLengthResponse("<?php");
            } else if (uri.endsWith(".jsp")) {
                return newFixedLengthResponse("<%.*%>");
            } else if (uri.endsWith(".war") || uri.endsWith(".ear") || uri.endsWith(".rar")) {
                return newFixedLengthResponse(".class");
            } else if (uri.endsWith("empty")) {
                return newFixedLengthResponse("");
            } else if (uri.endsWith(pValue)) {
                return newFixedLengthResponse(disclosureBody);
            }
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK, NanoHTTPD.MIME_HTML, DEFAULT_RESPONSE_STRING);
        }
    }

    /** Reflects HTML-escaped query param q (repro for zaproxy/zaproxy#9514). */
    private static class EchoHandler extends NanoServerHandler {
        public EchoHandler(String path) {
            super(path);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String q = getFirstParamValue(session, "q");
            if (q == null) {
                q = "";
            }
            String escaped =
                    q.replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                            .replace("\"", "&quot;");
            String body = "<html><body><p>echo: " + escaped + "</p></body></html>";
            return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, body);
        }
    }
}
