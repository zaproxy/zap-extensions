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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.testutils.NanoServerHandler;

class RelativePathConfusionScanRuleUnitTest
        extends ActiveScannerTest<RelativePathConfusionScanRule> {

    @Override
    protected RelativePathConfusionScanRule createScanner() {
        return new RelativePathConfusionScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(20)));
        assertThat(wasc, is(equalTo(20)));
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
    }

    @Test
    void shouldNotAlertIfAbsolutePathIsDetected() throws Exception {
        // Given
        String path = "/index.html";
        String body =
                "<html><head><style>"
                        + "body {background: url(http://google.com/abc.png);}"
                        + "div {background: url('http://google.com/abc.png');}"
                        + "</style></head><html>";
        this.nano.addHandler(createHandler(path, Response.Status.OK, body, ""));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"abc.png", "../abc.png", "'abc.png'", "\"../xxx/abc.png\"", "./abc.png"})
    void shouldAlertIfRelativePathIsDetected(String relativePath) throws Exception {
        // Given
        String path = "/index.html";
        String body = "<head><style>body {background: url(" + relativePath + ");}</style></head>";
        this.nano.addHandler(createHandler(path, Response.Status.OK, body, ""));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    private static NanoServerHandler createHandler(
            String path, Response.Status status, String body, String host) {
        return new NanoServerHandler(path) {
            @Override
            protected Response serve(IHTTPSession session) {
                if (session.getHeaders().get(HttpFieldsNames.HOST).equals(host) || host.isEmpty()) {
                    return newFixedLengthResponse(status, NanoHTTPD.MIME_HTML, body);
                }
                return newFixedLengthResponse(Response.Status.NOT_FOUND, NanoHTTPD.MIME_HTML, "");
            }
        };
    }
}
