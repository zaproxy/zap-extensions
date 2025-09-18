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
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link CommandInjectionScanRule}. */
class CommandInjectionScanRuleUnitTest extends CommandInjectionRuleTest<CommandInjectionScanRule> {

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 3;
            case MEDIUM:
            default:
                return recommendMax + 7;
            case HIGH:
                return recommendMax + 7;
            case INSANE:
                return recommendMax;
        }
    }

    @Override
    protected CommandInjectionScanRule createScanner() {
        return new CommandInjectionScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(78)));
        assertThat(wasc, is(equalTo(31)));
        assertThat(tags.size(), is(equalTo(14)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.HIPAA.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.PCI_DSS.getTag()), is(equalTo(true)));
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
                tags.get(CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ.getValue())));
    }

    @Test
    void shouldRaiseAlertIfResponseHasPasswdFileContentAndPayloadIsNullByteBased()
            throws HttpMalformedHeaderException {
        // Given
        NullByteVulnerableServerHandler vulnServerHandler =
                new NullByteVulnerableServerHandler("/", "p", Tech.Linux);
        nano.addHandler(vulnServerHandler);
        rule.init(getHttpMessage("/?p=a"), parent);
        rule.setAttackStrength(AttackStrength.INSANE);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldRaiseAlertIfResponseHasSystemINIFileContentAndPayloadIsNullByteBased()
            throws HttpMalformedHeaderException {
        // Given
        NullByteVulnerableServerHandler vulnServerHandler =
                new NullByteVulnerableServerHandler("/", "p", Tech.Windows);
        nano.addHandler(vulnServerHandler);
        rule.init(getHttpMessage("/?p=a"), parent);
        rule.setAttackStrength(AttackStrength.INSANE);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldRaiseAlertIfResponseHasEscapedHtmlControlPattern()
            throws HttpMalformedHeaderException {
        // Given
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "p");
                        if (value == null || !value.contains("/etc/passwd")) {
                            String regularContent =
                                    "<!DOCTYPE html><html><body>Nothing to see here.</body></html>";
                            return newFixedLengthResponse(regularContent);
                        }
                        String content =
                                "<!DOCTYPE html>\n"
                                        + "<html><body>"
                                        + "root&#x3a;x&#x3a;0&#x3a;0&#x3a;root&#x3a;&#x2f;root&#x3a;&#x2f;bin&#x2f;bash<br>"
                                        + "daemon&#x3a;x&#x3a;1&#x3a;1&#x3a;daemon&#x3a;&#x2f;usr&#x2f;sbin&#x3a;&#x2f;usr&#x2f;sbin&#x2f;nologin<br>"
                                        + "bin&#x3a;x&#x3a;2&#x3a;2&#x3a;bin&#x3a;&#x2f;bin&#x3a;&#x2f;usr&#x2f;sbin&#x2f;nologin<br>"
                                        + "sys&#x3a;x&#x3a;3&#x3a;3&#x3a;sys&#x3a;&#x2f;dev&#x3a;&#x2f;usr&#x2f;sbin&#x2f;nologin<br>"
                                        + "sync&#x3a;x&#x3a;4&#x3a;65534&#x3a;sync&#x3a;&#x2f;bin&#x3a;&#x2f;bin&#x2f;sync<br>"
                                        + "</body></html>";
                        return newFixedLengthResponse(content);
                    }
                });
        rule.init(getHttpMessage("/?p=a"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    private static Stream<Arguments> shouldReturnRelevantTechs() {
        return Stream.of(
                Arguments.of(Tech.Windows), Arguments.of(Tech.Linux), Arguments.of(Tech.MacOS));
    }

    @ParameterizedTest
    @MethodSource("shouldReturnRelevantTechs")
    void firstPayloadShouldNotHaveParamValue(Tech targetedTech)
            throws HttpMalformedHeaderException {
        // Given
        NullByteVulnerableServerHandler vulnServerHandler =
                new NullByteVulnerableServerHandler("/", "p", targetedTech);
        nano.addHandler(vulnServerHandler);
        rule.init(getHttpMessage("/?p=a"), parent);
        rule.setAttackStrength(AttackStrength.INSANE);
        // When
        rule.scan();
        // Then
        assertFalse(httpMessagesSent.get(0).getUrlParams().first().getValue().startsWith("a"));
        assertTrue(httpMessagesSent.get(1).getUrlParams().first().getValue().startsWith("a"));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / WHen
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        Alert alert = alerts.get(0);
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alert.getParam(), is(equalTo("qry")));
        assertThat(alert.getAttack(), is(equalTo("a;cat /etc/passwd ")));
        assertThat(alert.getEvidence(), is(equalTo("root:x:0:0")));
        assertThat(
                alert.getOtherInfo(),
                is(
                        equalTo(
                                "The scan rule was able to retrieve the content of a file or "
                                        + "command by sending [a;cat /etc/passwd ] to the operating "
                                        + "system running this application.")));
        Map<String, String> tags = alert.getTags();
        assertThat(tags, not(hasKey(CommonAlertTag.TEST_TIMING.getTag())));
    }
}
