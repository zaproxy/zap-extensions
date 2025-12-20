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
package org.zaproxy.zap.extension.scripts.scanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.commonlib.scanrules.AlertReferenceMetadata;
import org.zaproxy.addon.commonlib.scanrules.Confidence;
import org.zaproxy.addon.commonlib.scanrules.Risk;
import org.zaproxy.zap.testutils.TestUtils;

class ScriptScanRuleUtilsUnitTest extends TestUtils {

    @Test
    void shouldHandleCompleteAlertRefMetadata() {
        // Given
        AlertReferenceMetadata metadata = new AlertReferenceMetadata();
        metadata.setName("Alert Ref Name");
        metadata.setDescription("Alert Ref description");
        metadata.setSolution("Alert Ref solution");
        metadata.setReferences(
                List.of("https://example.com/reference-3", "https://example.com/reference-4"));
        metadata.setRisk(Risk.HIGH);
        metadata.setConfidence(Confidence.HIGH);
        metadata.setCweId(123);
        metadata.setWascId(456);
        metadata.setAlertTags(Map.of("name3", "value3"));
        metadata.setOtherInfo("More other Info");
        Alert.Builder builder = Alert.builder();
        // When
        ScriptScanRuleUtils.overrideWithAlertRefMetadata(builder, metadata);
        // Then
        Alert alert = builder.build();
        assertThat(alert.getName(), is(equalTo("Alert Ref Name")));
        assertThat(alert.getDescription(), is(equalTo("Alert Ref description")));
        assertThat(alert.getSolution(), is(equalTo("Alert Ref solution")));
        assertThat(
                alert.getReference(),
                is(equalTo("https://example.com/reference-3\nhttps://example.com/reference-4")));
        assertThat(alert.getRisk(), is(equalTo(Risk.HIGH.getValue())));
        assertThat(alert.getConfidence(), is(equalTo(Confidence.HIGH.getValue())));
        assertThat(alert.getCweId(), is(equalTo(123)));
        assertThat(alert.getWascId(), is(equalTo(456)));
        assertThat(
                alert.getTags(),
                is(
                        equalTo(
                                Map.of(
                                        "name3",
                                        "value3",
                                        "CWE-123",
                                        "https://cwe.mitre.org/data/definitions/123.html"))));
        assertThat(alert.getOtherInfo(), is(equalTo("More other Info")));
    }

    @Test
    void shouldOnlyOverrideNonNullValues() {
        // Given
        AlertReferenceMetadata metadata = new AlertReferenceMetadata();
        metadata.setName("Alert Ref Name");
        Alert.Builder builder =
                Alert.builder()
                        .setName("Original Name")
                        .setDescription("Original description")
                        .setSolution("Original solution");
        // When
        ScriptScanRuleUtils.overrideWithAlertRefMetadata(builder, metadata);
        // Then
        Alert alert = builder.build();
        assertThat(alert.getName(), is(equalTo("Alert Ref Name")));
        assertThat(alert.getDescription(), is(equalTo("Original description")));
        assertThat(alert.getSolution(), is(equalTo("Original solution")));
    }

    @Test
    void shouldNotThrowForNullOverride() {
        // Given
        Alert.Builder builder = Alert.builder().setName("Original Name");
        // When
        ScriptScanRuleUtils.overrideWithAlertRefMetadata(builder, null);
        // Then
        Alert alert = builder.build();
        assertThat(alert.getName(), is(equalTo("Original Name")));
    }

    @Test
    void shouldMergeMultipleReferences() {
        // Given
        List<String> references =
                List.of("https://example.com/reference-1", "https://example.com/reference-2");
        // When
        String result = ScriptScanRuleUtils.mergeReferences(references);
        // Then
        assertThat(
                result,
                is(equalTo("https://example.com/reference-1\nhttps://example.com/reference-2")));
    }
}
