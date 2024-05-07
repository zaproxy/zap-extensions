/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.accessControl;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link AccessControlAlertsProcessor}. */
class AccessControlAlertsProcessorUnitTest {

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
    }

    @AfterEach
    void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = AccessControlAlertsProcessor.getExampleAlerts();
        // Then
        assertThat(alerts, hasSize(2));
        assertAlert(alerts.get(0), 10101, "!accessControl.alert.authentication.name!", 287, 1);
        assertAlert(alerts.get(1), 10102, "!accessControl.alert.authorization.name!", 205, 2);
    }

    private static void assertAlert(
            Alert alert, int scanRuleId, String name, int cweId, int wascId) {
        assertThat(alert.getPluginId(), is(equalTo(scanRuleId)));
        assertThat(alert.getName(), is(equalTo(name)));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
        assertThat(alert.getCweId(), is(equalTo(cweId)));
        assertThat(alert.getWascId(), is(equalTo(wascId)));
        Map<String, String> tags = alert.getTags();
        assertThat(
                tags,
                allOf(
                        hasEntry(
                                "CWE-" + cweId,
                                "https://cwe.mitre.org/data/definitions/" + cweId + ".html"),
                        hasEntry(
                                CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag(),
                                CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue()),
                        hasEntry(
                                CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag(),
                                CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getValue())));
    }
}
