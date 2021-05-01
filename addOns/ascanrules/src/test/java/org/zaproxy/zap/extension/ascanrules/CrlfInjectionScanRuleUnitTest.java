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

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.ArrayList;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link CrlfInjectionScanRule}. */
public class CrlfInjectionScanRuleUnitTest extends ActiveScannerTest<CrlfInjectionScanRule> {

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 1;
            case MEDIUM:
            default:
                return recommendMax;
            case HIGH:
                return recommendMax;
            case INSANE:
                return recommendMax;
        }
    }

    @Override
    protected CrlfInjectionScanRule createScanner() {
        return new CrlfInjectionScanRule();
    }

    @Test
    public void shouldFindCrLfInjection() throws Exception {
        // Given
        String test = "/shouldFindCrLfInjection.php";
        ArrayList<String> tamperedHeaders = new ArrayList<>();

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String years = getFirstParamValue(session, "years");
                        if (years != null && years.contains("\r\n")) {
                            String[] parts = years.split("\r\n");
                            if (parts.length > 1) {
                                String[] headerParts = parts[1].split(":");
                                if (headerParts.length > 1) {
                                    String name = headerParts[0].trim();
                                    String value = headerParts[1].trim();
                                    Response response =
                                            newFixedLengthResponse("<html><body></body></html>");
                                    response.addHeader(name, value);
                                    tamperedHeaders.add(name + ": " + value);
                                    return response;
                                }
                            }
                        }
                        return newFixedLengthResponse("<html><body></body></html>");
                    }
                });
        // When
        HttpMessage msg = this.getHttpMessage(test + "?years=1");
        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("years"));
        boolean evidenceContainsOneOfTheTamperedHeaders = false;
        for (String tampered : tamperedHeaders) {
            if (alertsRaised.get(0).getEvidence().contains(tampered)) {
                evidenceContainsOneOfTheTamperedHeaders = true;
            }
        }
        assertThat(alertsRaised.get(0).getEvidence(), evidenceContainsOneOfTheTamperedHeaders);
    }
}
