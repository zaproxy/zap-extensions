/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link React2ShellScanRule}. */
class React2ShellScanRuleUnitTest extends ActiveScannerTest<React2ShellScanRule> {

    private static final String ERROR_RESPONSE =
            "0:{\"a\":\"$@1\",\"f\":\"\",\"b\":\"yd-J8UfWl70zwtaAy83s7\"}\n"
                    + "1:E{\"digest\":\"2971658870\"}";

    @Override
    protected React2ShellScanRule createScanner() {
        return new React2ShellScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(78)));
        assertThat(wasc, is(equalTo(32)));
        assertThat(tags.size(), is(equalTo(13)));
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

        assertThat(tags.containsKey(CommonAlertTag.HIPAA.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.PCI_DSS.getTag()), is(equalTo(true)));

        assertThat(tags.containsKey(PolicyTag.DEV_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));

        assertThat(tags.containsKey("CVE-2025-55182"), is(equalTo(true)));
        assertThat(tags.containsKey("CVE-2025-66478"), is(equalTo(true)));
    }

    @Test
    void shouldReturnExamples() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        Alert alert = alerts.get(0);
        assertThat(alert.getName(), is(equalTo("Remote Code Execution (React2Shell)")));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
        assertThat(alert.getParam(), is(equalTo("")));
        assertThat(alert.getAttack(), is(equalTo("[\"$1:a:a\"]")));
    }

    @Test
    void shouldTargetExpectedTech() {
        // Given / When
        TechSet allButFrameworks =
                techSetWithout(React2ShellScanRule.REACT, React2ShellScanRule.NEXT_JS);
        TechSet justReact = techSet(React2ShellScanRule.REACT);
        TechSet justNextJs = techSet(React2ShellScanRule.NEXT_JS);

        // Then
        assertThat(rule.targets(allButFrameworks), is(equalTo(false)));
        assertThat(rule.targets(justReact), is(equalTo(true)));
        assertThat(rule.targets(justNextJs), is(equalTo(true)));
    }

    @Test
    void shouldRaiseAlertIf500AndEvidence() throws HttpMalformedHeaderException {
        // Given
        this.nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        Response response =
                                newFixedLengthResponse(
                                        NanoHTTPD.Response.Status.INTERNAL_ERROR,
                                        NanoHTTPD.MIME_HTML,
                                        ERROR_RESPONSE);
                        return response;
                    }
                });
        rule.init(getHttpMessage("/"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getName(), is(equalTo("Remote Code Execution (React2Shell)")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("[\"$1:a:a\"]")));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("E{\"digest\"")));
    }

    @Test
    void shouldNotRaiseAlertIf200AndEvidence() throws HttpMalformedHeaderException {
        // Given
        this.nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        Response response =
                                newFixedLengthResponse(
                                        NanoHTTPD.Response.Status.OK,
                                        NanoHTTPD.MIME_HTML,
                                        ERROR_RESPONSE);
                        return response;
                    }
                });
        rule.init(getHttpMessage("/"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertIf500AndNoEvidence() throws HttpMalformedHeaderException {
        // Given
        this.nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        Response response =
                                newFixedLengthResponse(
                                        NanoHTTPD.Response.Status.INTERNAL_ERROR,
                                        NanoHTTPD.MIME_HTML,
                                        "<html><body>An error</body></html>");
                        return response;
                    }
                });
        rule.init(getHttpMessage("/"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }
}
