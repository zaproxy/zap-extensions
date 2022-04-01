/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link Spring4ShellScanRule}. */
class Spring4ShellScanRuleUnitTest extends ActiveScannerTest<Spring4ShellScanRule> {

    @Override
    protected Spring4ShellScanRule createScanner() {
        return new Spring4ShellScanRule();
    }

    @Test
    void shouldTargetSpringTech() {
        // Given
        TechSet techSet = techSet(Tech.SPRING);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetNonSpringTechs() {
        // Given
        TechSet techSet = techSetWithout(Tech.SPRING);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldBeInjectionCategory() {
        // Given
        Integer category = Category.INJECTION;
        // When
        Integer ruleCategory = rule.getCategory();
        // Then
        assertEquals(ruleCategory, category);
    }

    @Test
    void shouldIgnore400ResponseCodes() throws HttpMalformedHeaderException {
        // Given
        String path = "/Ignore400";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, "");
                    }
                });
        HttpMessage msg = getHttpMessage("GET", path, "");
        msg.getResponseHeader().setStatusCode(400);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(0));
    }

    @Test
    void shouldNotAlertOnNo400s() throws HttpMalformedHeaderException {
        // Given
        String path = "/notvulnerable";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        this.consumeBody(session);
                        return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, "");
                    }
                });
        HttpMessage msg = getHttpMessage("GET", path, "");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(2));
    }

    @Test
    void shouldAlertOnVulnerableGet() throws HttpMalformedHeaderException {
        // Given
        String path = "/getvulnerable";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        if (NanoHTTPD.Method.GET.equals(session.getMethod())
                                && session.getQueryParameterString()
                                        .contains(Spring4ShellScanRule.ATTACK)) {
                            this.consumeBody(session);
                            return newFixedLengthResponse(
                                    Response.Status.BAD_REQUEST, NanoHTTPD.MIME_HTML, "");
                        }
                        this.consumeBody(session);
                        return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, "");
                    }
                });
        HttpMessage msg = getHttpMessage("GET", path, "");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getName(), is(equalTo("Spring4Shell")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(3)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(2)));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("HTTP/1.1 400 Bad Request ")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo(Spring4ShellScanRule.ATTACK)));
    }

    @Test
    void shouldAlertOnVulnerablePost() throws HttpMalformedHeaderException {
        // Given
        String path = "/postvulnerable";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        if (NanoHTTPD.Method.POST.equals(session.getMethod())
                                && this.getBody(session).contains(Spring4ShellScanRule.ATTACK)) {
                            this.consumeBody(session);
                            return newFixedLengthResponse(
                                    Response.Status.BAD_REQUEST, NanoHTTPD.MIME_HTML, "");
                        }
                        this.consumeBody(session);
                        return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, "");
                    }
                });
        HttpMessage msg = getHttpMessage("GET", path, "");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getName(), is(equalTo("Spring4Shell")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(3)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(2)));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("HTTP/1.1 400 Bad Request ")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo(Spring4ShellScanRule.ATTACK)));
    }

    @Test
    void shouldNotAlertOnAll400s() throws HttpMalformedHeaderException {
        // Given
        String path = "/stillnotvulnerable";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        this.consumeBody(session);
                        return newFixedLengthResponse(
                                Response.Status.BAD_REQUEST, NanoHTTPD.MIME_HTML, "");
                    }
                });
        HttpMessage msg = getHttpMessage("GET", path, "");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(4));
    }

    @Test
    void shouldHandleNetworkErrors() throws HttpMalformedHeaderException {
        // Given
        String path = "/";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, "");
                    }
                });
        HttpMessage msg = getHttpMessage(path);
        rule.init(msg, parent);
        this.nano.stop();
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(0));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(78)));
        assertThat(wasc, is(equalTo(20)));
        assertThat(tags.size(), is(equalTo(5)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ.getValue())));
    }
}
