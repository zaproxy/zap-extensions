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
package org.zaproxy.addon.mcp.resources;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link AlertsResource}. */
class AlertsResourceUnitTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private ExtensionLoader extensionLoader;
    private ExtensionAlert extAlert;
    private AlertsResource resource;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extAlert = mock(ExtensionAlert.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionAlert.class)).willReturn(extAlert);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        resource = new AlertsResource();
    }

    @Test
    void shouldHaveCorrectUriAndName() {
        assertThat(resource.getUri(), equalTo("zap://alerts"));
        assertThat(resource.getName(), equalTo("alerts"));
    }

    @Test
    void shouldReturnEmptyArrayWhenExtensionAlertNotInstalled() {
        given(extensionLoader.getExtension(ExtensionAlert.class)).willReturn(null);

        String content = resource.readContent();

        assertThat(parseJsonArray(content).size(), equalTo(0));
    }

    @Test
    void shouldReturnSummaryWithRiskAsString() {
        Alert alert = new Alert(100, Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        alert.setAlertRef("100-1");
        given(extAlert.getAllAlerts()).willReturn(List.of(alert));

        String content = resource.readContent();
        JsonNode array = parseJsonArray(content);

        assertThat(array.size(), equalTo(1));
        assertThat(array.get(0).get("risk").asText(), equalTo(Alert.MSG_RISK[Alert.RISK_HIGH]));
        assertThat(array.get(0).get("name").asText(), equalTo("XSS"));
        assertThat(array.get(0).get("alertRef").asText(), equalTo("100-1"));
        assertThat(array.get(0).get("instanceCount").asInt(), equalTo(1));
        assertThat(array.get(0).get("instancesUri").asText(), equalTo("zap://alerts/100-1"));
    }

    @Test
    void shouldOrderAlertsByRiskHighestFirst() {
        Alert lowAlert = new Alert(100, Alert.RISK_LOW, Alert.CONFIDENCE_LOW, "Low");
        lowAlert.setAlertRef("100-1");
        Alert highAlert = new Alert(200, Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, "High");
        highAlert.setAlertRef("200-1");
        Alert mediumAlert = new Alert(300, Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, "Medium");
        mediumAlert.setAlertRef("300-1");
        given(extAlert.getAllAlerts()).willReturn(Arrays.asList(lowAlert, highAlert, mediumAlert));

        String content = resource.readContent();
        JsonNode array = parseJsonArray(content);

        assertThat(array.size(), equalTo(3));
        assertThat(array.get(0).get("risk").asText(), equalTo(Alert.MSG_RISK[Alert.RISK_HIGH]));
        assertThat(array.get(1).get("risk").asText(), equalTo(Alert.MSG_RISK[Alert.RISK_MEDIUM]));
        assertThat(array.get(2).get("risk").asText(), equalTo(Alert.MSG_RISK[Alert.RISK_LOW]));
    }

    @Test
    void shouldGroupAlertsByAlertRef() {
        Alert alert1 = new Alert(100, Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        alert1.setAlertRef("100-1");
        Alert alert2 = new Alert(100, Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        alert2.setAlertRef("100-1");
        given(extAlert.getAllAlerts()).willReturn(List.of(alert1, alert2));

        String content = resource.readContent();
        JsonNode array = parseJsonArray(content);

        assertThat(array.size(), equalTo(1));
        assertThat(array.get(0).get("instanceCount").asInt(), equalTo(2));
    }

    @Test
    void shouldReturnEmptyArrayWhenNoAlerts() {
        given(extAlert.getAllAlerts()).willReturn(Collections.emptyList());

        String content = resource.readContent();

        assertThat(parseJsonArray(content).size(), equalTo(0));
    }

    private static JsonNode parseJsonArray(String json) {
        try {
            return OBJECT_MAPPER.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JSON: " + json, e);
        }
    }
}
