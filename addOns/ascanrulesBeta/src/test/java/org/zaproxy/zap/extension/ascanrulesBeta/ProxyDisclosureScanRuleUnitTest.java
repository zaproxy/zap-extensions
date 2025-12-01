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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

class ProxyDisclosureScanRuleUnitTest extends ActiveScannerTest<ProxyDisclosureScanRule> {

    @Override
    protected ProxyDisclosureScanRule createScanner() {
        return new ProxyDisclosureScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(204)));
        assertThat(wasc, is(equalTo(45)));
        assertThat(tags.size(), is(equalTo(4)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.SYSTEMIC.getTag()),
                is(equalTo(CommonAlertTag.SYSTEMIC.getValue())));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "X-Forwarded-For: 127.0.0.1",
                "X-Forwarded-Port: 443",
                "X-Forwarded-Proto: https",
                "Via: 1.1 vegur"
            })
    void shouldNotAlertIfOriginalHasEvidence(String header)
            throws HttpMalformedHeaderException, URIException {
        // Given
        String test = "/";
        nano.addHandler(
                new NanoServerHandler(test) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String content = "<html>" + header + "</html>";
                        // ex: 26LnCSQHJLzRZJk:zHmOVzlRTrxQvsiQKppCGlQ7QfzQbg5W2h7j5x8q
                        session.getCookies()
                                .iterator()
                                .forEachRemaining(
                                        cookie ->
                                                System.out.println(
                                                        cookie
                                                                + ":"
                                                                + session.getCookies()
                                                                        .read(cookie)));
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, content);
                    }
                });
        HttpMessage msg = getHttpMessage(test);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(equalTo(0)));
    }

    @Test
    @Disabled
    void shouldRaiseAlertIfCookieIsReflectedAndMaxForwardsIsDecremented() throws Exception {
        String testPath = "/proxy-maxforward-cookie";
        // Handler:
        // - For TRACE requests, echoes random cookie value and max-forwards header
        // - For other requests, normal response
        nano.addHandler(
                new NanoServerHandler(testPath) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String cookieValue = null;
                        String maxForwards = session.getHeaders().get("max-forwards");
                        // Find the first cookie value (ZAP uses a random name, so just grab any)
                        String cookieHeader = session.getHeaders().get("cookie");
                        if (cookieHeader != null && cookieHeader.contains("=")) {
                            cookieValue = cookieHeader.split("=")[1];
                        }
                        if ("TRACE".equals(session.getMethod().name())) {
                            StringBuilder content = new StringBuilder("<html>");
                            if (cookieValue != null) {
                                content.append(cookieValue);
                            }
                            if (maxForwards != null) {
                                content.append(" Max-Forwards:").append(maxForwards);
                            }
                            content.append("</html>");
                            return newFixedLengthResponse(
                                    Response.Status.OK, NanoHTTPD.MIME_HTML, content.toString());
                        }
                        // Default response for non-TRACE
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, "<html>Hello!</html>");
                    }
                });

        HttpMessage msg = getHttpMessage(testPath); // This will be GET by default
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(equalTo(1)));
        // Optionally, check evidence contains a cookie value and/or max-forwards
        String evidence = alertsRaised.get(0).getEvidence();
        assertThat(evidence, org.hamcrest.Matchers.containsString("Max-Forwards"));
    }

    @Test
    @Disabled
    void shouldRaiseAlertWhenTraceResponseHasProxyHeaderEvidenceNotInOriginal() throws Exception {
        String testPath = "/trigger-proxy-alert";
        nano.addHandler(
                new NanoServerHandler(testPath) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        if ("TRACE".equals(session.getMethod().name())) {
                            String cookieValue =
                                    session.getCookies()
                                            .read(session.getCookies().iterator().next());
                            // Return body with proxy header evidence
                            return newFixedLengthResponse(
                                    Response.Status.OK,
                                    NanoHTTPD.MIME_HTML,
                                    """
                    <html>
                    X-Forwarded-For: 127.0.0.1
                    max-forwards: 3
                    %s
                    </html>"""
                                            .formatted(cookieValue));
                        }
                        // Original GET does NOT contain proxy header evidence
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, "<html>Hello!</html>");
                    }
                });

        HttpMessage msg = getHttpMessage(testPath); // Initial GET
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then: Should trigger an alert
        assertThat(alertsRaised, hasSize(equalTo(1)));
        assertThat(alertsRaised.get(0).getEvidence(), containsString("X-Forwarded-For"));
    }
}
