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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

class SourceCodeDisclosureGitScanRuleUnitTest
        extends ActiveScannerTest<SourceCodeDisclosureGitScanRule> {

    @Override
    protected SourceCodeDisclosureGitScanRule createScanner() {
        return new SourceCodeDisclosureGitScanRule();
    }

    @BeforeEach
    void init() {
        Control.initSingletonForTesting(Model.getSingleton(), mock(ExtensionLoader.class));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(541)));
        assertThat(wasc, is(equalTo(34)));
        assertThat(tags.size(), is(equalTo(4)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        Alert alert = alerts.get(0);
        Map<String, String> tags = alert.getTags();
        assertThat(tags.size(), is(equalTo(5)));
        assertThat(tags, hasKey("CWE-541"));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()));
        assertThat(tags, hasKey(PolicyTag.QA_FULL.getTag()));
        assertThat(tags, hasKey(PolicyTag.PENTEST.getTag()));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldFindGitRepoExposed() throws Exception {
        // Given
        this.nano.addHandler(new GitServerHandler());

        HttpSender realSender = new HttpSender(HttpSender.ACTIVE_SCANNER_INITIATOR);
        when(parent.getHttpSender()).thenReturn(realSender);

        String url = "http://127.0.0.1:" + nano.getListeningPort() + "/custom/Target.java";
        HttpMessage msg = new HttpMessage(new URI(url, true));
        msg.setResponseHeader("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");

        rule.init(msg, parent);
        rule.setAttackStrength(AttackStrength.HIGH);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getName(), containsString("Source Code Disclosure"));
        assertThat(alertsRaised.get(0).getEvidence(), containsString("Target"));
    }

    private static class GitServerHandler extends NanoServerHandler {

        private static final byte[] GIT_INDEX_BYTES =
                new byte[] {
                    (byte) 0x44, (byte) 0x49, (byte) 0x52, (byte) 0x43, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
                    (byte) 0x69, (byte) 0x47, (byte) 0xC1, (byte) 0xDF, (byte) 0x34, (byte) 0x00,
                    (byte) 0x5F, (byte) 0x7F, (byte) 0x69, (byte) 0x47, (byte) 0xC1, (byte) 0xDF,
                    (byte) 0x34, (byte) 0x00, (byte) 0x5F, (byte) 0x7F, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x23, (byte) 0x00, (byte) 0x00, (byte) 0x0A, (byte) 0x9C,
                    (byte) 0x00, (byte) 0x00, (byte) 0x81, (byte) 0xA4, (byte) 0x00, (byte) 0x00,
                    (byte) 0x03, (byte) 0xE8, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0xE8,
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x17, (byte) 0x63, (byte) 0xBC,
                    (byte) 0x1A, (byte) 0xD4, (byte) 0xCF, (byte) 0xD9, (byte) 0x45, (byte) 0x45,
                    (byte) 0x28, (byte) 0xA0, (byte) 0x62, (byte) 0x73, (byte) 0x69, (byte) 0xC8,
                    (byte) 0xB9, (byte) 0xAC, (byte) 0x53, (byte) 0xDD, (byte) 0x0B, (byte) 0x87,
                    (byte) 0x00, (byte) 0x0B, (byte) 0x54, (byte) 0x61, (byte) 0x72, (byte) 0x67,
                    (byte) 0x65, (byte) 0x74, (byte) 0x2E, (byte) 0x6A, (byte) 0x61, (byte) 0x76,
                    (byte) 0x61, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00, (byte) 0xF0, (byte) 0x04, (byte) 0xE1, (byte) 0xED,
                    (byte) 0xE0, (byte) 0x89, (byte) 0xB0, (byte) 0x26, (byte) 0x3A, (byte) 0xC5,
                    (byte) 0x7C, (byte) 0x88, (byte) 0xF5, (byte) 0x9D, (byte) 0xDE, (byte) 0x2A,
                    (byte) 0x6F, (byte) 0x15, (byte) 0x42, (byte) 0x64
                };

        private static final byte[] GIT_OBJECT_BYTES =
                new byte[] {
                    (byte) 0x78, (byte) 0x01, (byte) 0x4B, (byte) 0xCA, (byte) 0xC9, (byte) 0x4F,
                    (byte) 0x52, (byte) 0x30, (byte) 0x32, (byte) 0x66, (byte) 0x28, (byte) 0x28,
                    (byte) 0x4D, (byte) 0xCA, (byte) 0xC9, (byte) 0x4C, (byte) 0x56, (byte) 0x48,
                    (byte) 0xCE, (byte) 0x49, (byte) 0x2C, (byte) 0x2E, (byte) 0x56, (byte) 0x08,
                    (byte) 0x49, (byte) 0x2C, (byte) 0x4A, (byte) 0x4F, (byte) 0x2D, (byte) 0x51,
                    (byte) 0xA8, (byte) 0xAE, (byte) 0xE5, (byte) 0x02, (byte) 0x00, (byte) 0xA5,
                    (byte) 0xEE, (byte) 0x0A, (byte) 0x83
                };

        public GitServerHandler() {
            super("/");
        }

        @Override
        public Response serve(IHTTPSession session) {
            String uri = session.getUri();

            if (uri.endsWith("Target.java")) {
                return newFixedLengthResponse(
                        Response.Status.OK, "text/html", "<html><body>Target Code</body></html>");
            }
            if (uri.endsWith("/.git") || uri.endsWith("/.git/")) {
                return newFixedLengthResponse(Response.Status.FORBIDDEN, "text/html", "Forbidden");
            }
            if (uri.endsWith(".git/HEAD")) {
                return newFixedLengthResponse(
                        Response.Status.OK, "text/plain", "ref: refs/heads/master\n");
            }
            if (uri.endsWith(".git/config")) {
                return newFixedLengthResponse(
                        Response.Status.OK,
                        "text/plain",
                        "[core]\n\trepositoryformatversion = 0\n");
            }
            if (uri.endsWith(".git/index")) {
                return newFixedLengthResponse(
                        Response.Status.OK,
                        "application/octet-stream",
                        new ByteArrayInputStream(GIT_INDEX_BYTES),
                        GIT_INDEX_BYTES.length);
            }
            if (uri.contains(".git/objects")) {
                return newFixedLengthResponse(
                        Response.Status.OK,
                        "application/octet-stream",
                        new ByteArrayInputStream(GIT_OBJECT_BYTES),
                        GIT_OBJECT_BYTES.length);
            }
            return newFixedLengthResponse(Response.Status.NOT_FOUND, "text/html", "Not Found");
        }
    }
}
