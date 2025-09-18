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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

class XpathInjectionScanRuleUnitTest extends ActiveScannerTest<XpathInjectionScanRule> {

    private static final String TEST_ERROR_STRING = "FooExceptionBar";

    @Override
    protected XpathInjectionScanRule createScanner() {
        return new XpathInjectionScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(643)));
        assertThat(wasc, is(equalTo(39)));
        assertThat(tags.size(), is(equalTo(15)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_09_XPATH.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.HIPAA.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.PCI_DSS.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.CUSTOM_PAYLOADS.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.API.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.SEQUENCE.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_09_XPATH.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_09_XPATH.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts, hasSize(1));
        Alert alert = alerts.get(0);
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
        assertThat(alert.getAlertRef(), is(equalTo("90021")));
    }

    @Test
    void shouldRaiseAlertIfResponseContainsExpectedErrorForInjectedInput()
            throws HttpMalformedHeaderException {
        // Given
        String testPath = "/shouldRaiseAlertIfResponseContainsExpectedErrorForInjectedInput/";
        this.nano.addHandler(createXpathHandler(testPath, "XPathException"));
        HttpMessage msg = getHttpMessage(testPath + "?query=xxx");
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("XPathException")));
    }

    @Test
    void shouldNotRaiseAlertIfResponseDoesNotContainExpectedErrorForInjectedInput()
            throws HttpMalformedHeaderException {
        // Given
        String testPath =
                "/shouldNotRaiseAlertIfResponseDoesNotContainExpectedErrorForInjectedInput/";
        this.nano.addHandler(createXpathHandler(testPath, "FooBar"));
        HttpMessage msg = getHttpMessage(testPath + "?query=xxx");
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldRaiseAlertIfResponseContainsExpectedCustomErrorForInjectedInput()
            throws HttpMalformedHeaderException {
        // Given
        String testPath = "/shouldRaiseAlertIfResponseContainsExpectedCustomErrorForInjectedInput/";
        this.nano.addHandler(createXpathHandler(testPath, TEST_ERROR_STRING));
        HttpMessage msg = getHttpMessage(testPath + "?query=xxx");
        this.rule.init(msg, this.parent);
        XpathInjectionScanRule.setErrorProvider(() -> List.of(TEST_ERROR_STRING));
        // When
        this.rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo(TEST_ERROR_STRING)));
    }

    private static NanoServerHandler createXpathHandler(String path, String indicator) {
        return new NanoServerHandler(path) {
            @Override
            protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                String site = getFirstParamValue(session, "query");
                if (site.equals("\"'")) {
                    return newFixedLengthResponse(
                            "<html><body>%s</body></html>".formatted(indicator));
                } else {
                    return newFixedLengthResponse("<html><body></body></html>");
                }
            }
        };
    }
}
