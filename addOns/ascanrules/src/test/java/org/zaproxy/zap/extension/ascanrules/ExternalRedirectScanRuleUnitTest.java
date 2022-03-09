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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link ExternalRedirectScanRule}. */
class ExternalRedirectScanRuleUnitTest extends ActiveScannerTest<ExternalRedirectScanRule> {

    @Override
    protected ExternalRedirectScanRule createScanner() {
        return new ExternalRedirectScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(601)));
        assertThat(wasc, is(equalTo(38)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CLNT_04_OPEN_REDIR.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CLNT_04_OPEN_REDIR.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CLNT_04_OPEN_REDIR.getValue())));
    }

    @Test
    void shouldHaveHighRisk() {
        // Given / When
        int risk = rule.getRisk();
        // Then
        assertThat(risk, is(equalTo(Alert.RISK_HIGH)));
    }

    @Test
    void shouldReportSimpleRedirect() throws Exception {
        // Given
        String test = "/shouldReportSimpleRedirect/";

        nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String site = getFirstParamValue(session, "site");
                        if (site != null && site.length() > 0) {
                            Response response =
                                    newFixedLengthResponse(
                                            NanoHTTPD.Response.Status.REDIRECT,
                                            NanoHTTPD.MIME_HTML,
                                            "Redirect");
                            response.addHeader("Location", site);
                            return response;
                        }
                        String response = "<html><body></body></html>";
                        return newFixedLengthResponse(response);
                    }
                });
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("site"));
        assertThat(alertsRaised.get(0).getEvidence().endsWith(".owasp.org"), equalTo(true));
    }

    @Test
    void shouldReportDoubleEncodedRedirect() throws Exception {
        // Given
        String test = "/shouldReportDoubleEncodedRedirect/";

        nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String site = getFirstParamValue(session, "site");
                        if (site != null && site.length() > 0 && !site.contains(".")) {
                            Response response =
                                    newFixedLengthResponse(
                                            NanoHTTPD.Response.Status.REDIRECT,
                                            NanoHTTPD.MIME_HTML,
                                            "Redirect");
                            response.addHeader("Location", site);
                            return response;
                        }
                        String response = "<html><body></body></html>";
                        return newFixedLengthResponse(response);
                    }
                });
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("site"));
        assertThat(alertsRaised.get(0).getEvidence().endsWith("%2eowasp%2eorg"), equalTo(true));
    }
}
