/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link BufferOverflowScanRule}. */
class BufferOverflowScanRuleUnitTest extends ActiveScannerTest<BufferOverflowScanRule> {

    @Override
    protected BufferOverflowScanRule createScanner() {
        return new BufferOverflowScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(120)));
        assertThat(wasc, is(equalTo(7)));
        assertThat(tags.size(), is(equalTo(2)));
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
    }

    @Test
    void shouldTargetCTech() {
        // Given
        TechSet techSet = techSet(Tech.C);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetNonCTechs() {
        // Given
        TechSet techSet = techSetWithout(Tech.C);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldCreateAlert() throws Exception {
        // Given
        String test = "/shouldReportBufferOverflowIssue/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        if (name != null && name.length() > 1000) {
                            Response response =
                                    newFixedLengthResponse(
                                            NanoHTTPD.Response.Status.INTERNAL_ERROR,
                                            NanoHTTPD.MIME_HTML,
                                            "500 error handling request");
                            response.addHeader("Connection", "close");
                            return response;
                        }
                        String response = "<html><body></body></html>";
                        return newFixedLengthResponse(response);
                    }
                });
        // When
        HttpMessage msg = this.getHttpMessage(test + "?name=xxx");
        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("Connection: close"));
    }
}
