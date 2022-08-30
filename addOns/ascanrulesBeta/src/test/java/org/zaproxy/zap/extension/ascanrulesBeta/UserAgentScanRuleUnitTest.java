/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/** Unit test for {@link UserAgentScanRule}. */
class UserAgentScanRuleUnitTest extends ActiveScannerTest<UserAgentScanRule> {

    @Override
    protected UserAgentScanRule createScanner() {
        return new UserAgentScanRule();
    }

    @Override
    protected boolean isIgnoreAlertsRaisedInSendReasonableNumberOfMessages() {
        return true;
    }

    @Test
    void shouldHaveInfoRisk() {
        // Given / When
        int risk = rule.getRisk();
        // Then
        assertThat(risk, is(equalTo(Alert.RISK_INFO)));
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        Alert alert = alerts.get(0);
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        assertThat(alert.getTags().size(), is(equalTo(1)));
        assertThat(alert.getTags(), hasKey(CommonAlertTag.CUSTOM_PAYLOADS.getTag()));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_INFO)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alert.getParam(), is(equalTo("Header " + HttpHeader.USER_AGENT)));
        assertThat(alert.getAttack(), is(equalTo("ExampleBot 1.1")));
    }
}
