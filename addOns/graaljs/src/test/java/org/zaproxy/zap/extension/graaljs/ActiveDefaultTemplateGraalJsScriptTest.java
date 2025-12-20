/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.graaljs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.testutils.AlertReferenceError;

class ActiveDefaultTemplateGraalJsScriptTest extends GraalJsActiveScriptScanRuleTestUtils {
    @Override
    public Path getScriptPath() throws Exception {
        return Path.of(
                getClass()
                        .getResource("/scripts/templates/active/Active default template GraalJS.js")
                        .toURI());
    }

    @Override
    protected boolean isIgnoreAlertsRaisedInSendReasonableNumberOfMessages() {
        return true;
    }

    @Override
    public boolean isAllowedReferenceError(
            AlertReferenceError.Cause cause, String reference, Object detail) {
        // These are example.org references.
        return true;
    }

    @Test
    void shouldRaiseAlert() throws Exception {
        // Given
        rule.init(getHttpMessage("/path?param=value"), this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getPluginId(), is(equalTo(12345)));
        assertThat(alert.getAlertRef(), is(equalTo("12345-1")));
        assertThat(alert.getName(), is(equalTo("Active Vulnerability Title")));
        assertThat(alert.getDescription(), is(equalTo("Full description")));
        assertThat(alert.getSolution(), is(equalTo("The solution")));
        assertThat(
                alert.getReference(),
                is(
                        equalTo(
                                "https://www.example.org/reference1\nhttps://www.example.org/reference2")));
        assertThat(alert.getOtherInfo(), is(equalTo("Any other Info")));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_INFO)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        assertThat(alert.getTags(), is(equalTo(Map.of("name1", "value1", "name2", "value2"))));
        assertThat(alert.getMsgUri().getPathQuery(), is(equalTo("/path?param=Your attack")));
        assertThat(alert.getParam(), is(equalTo("param")));
        assertThat(alert.getAttack(), is(equalTo("Your attack")));
        assertThat(alert.getEvidence(), is(equalTo("Evidence")));
    }
}
