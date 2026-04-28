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
package org.zaproxy.addon.wstgmapper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;

import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventPublisher;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;
import org.zaproxy.zap.model.Target;

/**
 * Unit tests for {@link WstgMapperAlertConsumer}.
 *
 * <p>These checks exercise the event-to-checklist mapping flow and the filtering rules that ignore
 * low-value alerts before they affect the dashboard.
 */
class WstgMapperAlertConsumerTest {

    private static final EventPublisher STUB_PUBLISHER = () -> "stub-publisher";

    private WstgMapperChecklistManager checklistManager;
    private WstgMapperAlertConsumer consumer;

    @BeforeEach
    void setUp() throws IOException {
        checklistManager = new WstgMapperChecklistManager(null);
        consumer = new WstgMapperAlertConsumer(new WstgMapperMappingManager(), checklistManager);
    }

    @Test
    void mappedPluginTriggersChecklistEntries() {
        consumer.eventReceived(alertEvent("10010"));

        assertThat(checklistManager.getTriggeredIds(), contains("WSTG-SESS-02"));
    }

    @Test
    void informationalAlertDoesNotTriggerChecklistEntries() {
        consumer.eventReceived(
                alertEvent("10010", Map.of(AlertEventPublisher.RISK_STRING, "Informational")));

        assertThat(checklistManager.isTriggered("WSTG-SESS-02"), is(false));
    }

    @Test
    void lowConfidenceAlertWithoutEvidenceDoesNotTriggerChecklistEntries() {
        consumer.eventReceived(alertEvent("10010", Map.of("confidenceString", "Low")));

        assertThat(checklistManager.isTriggered("WSTG-SESS-02"), is(false));
    }

    @Test
    void lowConfidenceAlertWithEvidenceCanTriggerChecklistEntries() {
        consumer.eventReceived(
                alertEvent(
                        "10010",
                        Map.of("confidenceString", "Low", "evidence", "session cookie observed")));

        assertThat(checklistManager.isTriggered("WSTG-SESS-02"), is(true));
    }

    @Test
    void existingMappedAlertCanBootstrapChecklistEntries() {
        Alert alert = new Alert(10010, Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, "Example Alert");
        alert.setEvidence("session cookie observed");

        consumer.consumeAlert(alert);

        assertThat(checklistManager.isTriggered("WSTG-SESS-02"), is(true));
    }

    @Test
    void existingInformationalAlertDoesNotBootstrapChecklistEntries() {
        Alert alert = new Alert(10010, Alert.RISK_INFO, Alert.CONFIDENCE_MEDIUM, "Example Alert");
        alert.setEvidence("session cookie observed");

        consumer.consumeAlert(alert);

        assertThat(checklistManager.isTriggered("WSTG-SESS-02"), is(false));
    }

    @Test
    void alertNameCanDetectTechnologyCaseInsensitively() {
        consumer.eventReceived(
                alertEvent("999999", Map.of(AlertEventPublisher.NAME, "Wappalyzer: MySQL")));

        assertThat(checklistManager.getDetectedTechnologies(), containsInAnyOrder("mysql"));
    }

    @Test
    void invalidPluginIdDoesNotThrow() {
        consumer.eventReceived(alertEvent("not-a-number"));
    }

    private static Event alertEvent(String pluginId) {
        return alertEvent(pluginId, Map.of());
    }

    private static Event alertEvent(String pluginId, Map<String, String> extraParams) {
        java.util.Map<String, String> params = new java.util.HashMap<>();
        params.put(AlertEventPublisher.PLUGIN_ID, pluginId);
        params.put(AlertEventPublisher.RISK_STRING, "Medium");
        params.put(AlertEventPublisher.NAME, "Example Alert");
        params.putAll(extraParams);
        return new Event(
                STUB_PUBLISHER, AlertEventPublisher.ALERT_ADDED_EVENT, new Target(), params);
    }
}
