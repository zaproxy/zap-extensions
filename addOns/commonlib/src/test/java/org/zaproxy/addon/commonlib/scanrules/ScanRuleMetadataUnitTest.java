/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.scanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.utils.I18N;

class ScanRuleMetadataUnitTest {

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ENGLISH);
    }

    @Test
    void shouldParseMetadataYaml() {
        // Given
        String yaml =
                """
id: 12345
name: Active Vulnerability Title
description: Full description
solution: The solution
references:
  - https://example.com/reference-1
  - https://example.com/reference-2
category: INJECTION  # info_gather, browser, server, misc, injection
risk: INFO  # info, low, medium, high
confidence: LOW  # false_positive, low, medium, high, user_confirmed
cweId: 123
wascId: 456
alertTags:
  name1: value1
  name2: value2
otherInfo: Any other Info
status: alpha
codeLink: https://www.example.com/codelink
helpLink: https://www.example.com/helplink
alertRefOverrides:
  12345-1:
    name: Alert Ref Override 1
  12345-2:
    name: Alert Ref Override 2
""";
        // When
        var metadata = ScanRuleMetadata.fromYaml(yaml);
        // Then
        assertThat(metadata.getId(), is(equalTo(12345)));
        assertThat(metadata.getName(), is(equalTo("Active Vulnerability Title")));
        assertThat(metadata.getDescription(), is(equalTo("Full description")));
        assertThat(metadata.getSolution(), is(equalTo("The solution")));
        assertThat(
                metadata.getReferences(),
                contains("https://example.com/reference-1", "https://example.com/reference-2"));
        assertThat(metadata.getCategory(), is(equalTo(Category.INJECTION)));
        assertThat(metadata.getRisk(), is(equalTo(Risk.INFO)));
        assertThat(metadata.getConfidence(), is(equalTo(Confidence.LOW)));
        assertThat(metadata.getCweId(), is(equalTo(123)));
        assertThat(metadata.getWascId(), is(equalTo(456)));
        assertThat(
                metadata.getAlertTags(), is(equalTo(Map.of("name1", "value1", "name2", "value2"))));
        assertThat(metadata.getOtherInfo(), is(equalTo("Any other Info")));
        assertThat(metadata.getStatus(), is(equalTo(AddOn.Status.alpha)));
        assertThat(metadata.getCodeLink(), is(equalTo("https://www.example.com/codelink")));
        assertThat(metadata.getHelpLink(), is(equalTo("https://www.example.com/helplink")));
        assertThat(metadata.getAlertRefOverrides().size(), is(equalTo(2)));
        assertThat(
                metadata.getAlertRefOverrides().get("12345-1").getName(),
                is(equalTo("Alert Ref Override 1")));
        assertThat(
                metadata.getAlertRefOverrides().get("12345-2").getName(),
                is(equalTo("Alert Ref Override 2")));
    }

    @Test
    void shouldHandleAllAlertRefOverrideFields() {
        // Given
        String yaml =
                """
id: 12345
name: Active Vulnerability Title
alertRefOverrides:
  12345-1:
    name: Alert Ref 1
    description: Full description
    solution: The solution
    references:
      - https://example.com/reference-1
      - https://example.com/reference-2
    risk: INFO  # info, low, medium, high
    confidence: LOW  # false_positive, low, medium, high, user_confirmed
    cweId: 0
    wascId: 0
    alertTags:
      name1: value1
      name2: value2
    otherInfo: Any other Info
""";
        // When
        AlertReferenceMetadata metadata =
                ScanRuleMetadata.fromYaml(yaml).getAlertRefOverrides().get("12345-1");
        // Then
        assertThat(metadata.getName(), is(equalTo("Alert Ref 1")));
        assertThat(metadata.getDescription(), is(equalTo("Full description")));
        assertThat(metadata.getSolution(), is(equalTo("The solution")));
        assertThat(
                metadata.getReferences(),
                contains("https://example.com/reference-1", "https://example.com/reference-2"));
        assertThat(metadata.getRisk(), is(equalTo(Risk.INFO)));
        assertThat(metadata.getConfidence(), is(equalTo(Confidence.LOW)));
        assertThat(metadata.getCweId(), is(equalTo(0)));
        assertThat(metadata.getWascId(), is(equalTo(0)));
        assertThat(
                metadata.getAlertTags(), is(equalTo(Map.of("name1", "value1", "name2", "value2"))));
        assertThat(metadata.getOtherInfo(), is(equalTo("Any other Info")));
    }

    @Test
    void shouldWorkWithCaseInsensitiveEnumValues() {
        // Given
        String yaml =
                "id: 12345\n"
                        + "name: Test Scan Rule\n"
                        + "category: iNjEcTiOn\n"
                        + "risk: iNfO\n"
                        + "confidence: lOw\n"
                        + "status: aLpHa";
        // When
        var metadata = ScanRuleMetadata.fromYaml(yaml);
        // Then
        assertThat(metadata.getId(), is(equalTo(12345)));
        assertThat(metadata.getName(), is(equalTo("Test Scan Rule")));
        assertThat(metadata.getCategory(), is(equalTo(Category.INJECTION)));
        assertThat(metadata.getRisk(), is(equalTo(Risk.INFO)));
        assertThat(metadata.getConfidence(), is(equalTo(Confidence.LOW)));
        assertThat(metadata.getStatus(), is(equalTo(AddOn.Status.alpha)));
    }

    @Test
    void shouldIgnoreUnknownYamlFields() {
        // Given
        String yaml = "id: 12345\nname: Test Scan Rule\nsong: Never Gonna Give You Up\n";
        // When
        var metadata = ScanRuleMetadata.fromYaml(yaml);
        // Then
        assertThat(metadata.getId(), is(equalTo(12345)));
        assertThat(metadata.getName(), is(equalTo("Test Scan Rule")));
    }

    @Test
    void shouldThrowExceptionWhenIdIsMissing() {
        // Given
        String yaml = "name: Test Scan Rule\n";
        // When / Then
        assertThrows(RuntimeException.class, () -> ScanRuleMetadata.fromYaml(yaml));
    }

    @Test
    void shouldThrowExceptionWhenNameIsMissing() {
        // Given
        String yaml = "id: 12345\n";
        // When / Then
        assertThrows(RuntimeException.class, () -> ScanRuleMetadata.fromYaml(yaml));
    }

    @Test
    void shouldThrowExceptionWhenYamlIsInvalid() {
        // Given
        String yaml = "not yaml";
        // When / Then
        assertThrows(RuntimeException.class, () -> ScanRuleMetadata.fromYaml(yaml));
    }
}
