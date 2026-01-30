/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.llm.ui;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;

class LlmAppendAlertMenuUnitTest {

    @Test
    void shouldBuildStructuredAlertPayload() throws Exception {
        // Given
        Alert alert = new Alert(1, Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "Test Alert");
        alert.setDescription("Alert description");
        alert.setUri("http://example.com/test");
        alert.setParam("param");
        alert.setAttack("attack");
        alert.setEvidence("evidence");
        alert.setOtherInfo("other info");

        // When
        Map<String, Object> payload = LlmAppendAlertMenu.buildStructuredPayload(alert);

        // Then
        assertThat(payload.get("type"), is("alert"));
        assertThat(payload.get("name"), is("Test Alert"));
        assertThat(payload.get("risk"), is(Alert.MSG_RISK[Alert.RISK_HIGH]));
        assertThat(payload.get("confidence"), is(Alert.MSG_CONFIDENCE[Alert.CONFIDENCE_MEDIUM]));
        assertThat(payload.get("description"), is("Alert description"));
        assertThat(payload.get("uri"), is("http://example.com/test"));
        assertThat(payload.get("param"), is("param"));
        assertThat(payload.get("attack"), is("attack"));
        assertThat(payload.get("evidence"), is("evidence"));
        assertThat(payload.get("otherInfo"), is("other info"));
    }

    @Test
    void shouldSkipBlankAlertFields() throws Exception {
        // Given
        Alert alert = new Alert(1, Alert.RISK_LOW, Alert.CONFIDENCE_LOW, "Test Alert");
        alert.setParam("");
        alert.setAttack("  ");
        alert.setOtherInfo(null);

        // When
        Map<String, Object> payload = LlmAppendAlertMenu.buildStructuredPayload(alert);

        // Then
        assertThat(payload.get("type"), is("alert"));
        assertThat(payload.get("name"), is("Test Alert"));
        assertThat(payload, not(hasKey("param")));
        assertThat(payload, not(hasKey("attack")));
        assertThat(payload, not(hasKey("otherInfo")));
    }
}
