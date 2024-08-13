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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class SlackerCookieScanRuleUnitTest extends ActiveScannerTest<SlackerCookieScanRule> {

    @Override
    protected SlackerCookieScanRule createScanner() {
        return new SlackerCookieScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(205)));
        assertThat(wasc, is(equalTo(45)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given /  When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts, hasSize(1));
        Alert alert = alerts.get(0);
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_INFO)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        assertThat(
                alert.getOtherInfo(),
                is(
                        equalTo(
                                "Cookies that don't have "
                                        + "expected effects can reveal flaws in application logic. In "
                                        + "the worst case, this can reveal where authentication via cookie "
                                        + "token(s) is not actually enforced.\n"
                                        + "These cookies affected the response: oops\n"
                                        + "These cookies did NOT affect the response: bar,foo\n")));
    }
}
