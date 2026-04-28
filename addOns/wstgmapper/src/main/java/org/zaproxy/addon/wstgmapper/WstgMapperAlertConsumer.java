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

import java.util.Comparator;
import java.util.Locale;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

/**
 * Consumes alert events from ZAP's event bus and maps them to WSTG coverage signals.
 *
 * <p>It marks matching WSTG tests as triggered when an alert's plugin ID is known, and it also
 * extracts simple technology hints from alert names to improve checklist filtering.
 */
public class WstgMapperAlertConsumer implements EventConsumer {

    private static final Logger LOGGER = LogManager.getLogger(WstgMapperAlertConsumer.class);

    private final WstgMapperMappingManager mappingManager;
    private final WstgMapperChecklistManager checklistManager;

    public WstgMapperAlertConsumer(
            WstgMapperMappingManager mappingManager, WstgMapperChecklistManager checklistManager) {
        this.mappingManager = mappingManager;
        this.checklistManager = checklistManager;
    }

    public void register() {
        ZAP.getEventBus()
                .registerConsumer(
                        this,
                        AlertEventPublisher.getPublisher().getPublisherName(),
                        AlertEventPublisher.ALERT_ADDED_EVENT,
                        AlertEventPublisher.ALERT_CHANGED_EVENT);
    }

    public void unregister() {
        ZAP.getEventBus().unregisterConsumer(this);
    }

    public void bootstrapExistingAlerts() {
        try {
            ExtensionAlert extensionAlert =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
            if (extensionAlert == null) {
                return;
            }
            for (Alert alert : extensionAlert.getAllAlerts()) {
                consumeAlert(alert);
            }
        } catch (Exception e) {
            LOGGER.debug("WSTG Mapper alert bootstrap skipped: {}", e.getMessage());
        }
    }

    @Override
    public void eventReceived(Event event) {
        Map<String, String> params = event.getParameters();
        if (params == null) {
            return;
        }
        String pluginIdStr = params.get(AlertEventPublisher.PLUGIN_ID);
        if (pluginIdStr == null) {
            return;
        }
        String alertName = params.get(AlertEventPublisher.NAME);
        try {
            int pluginId = Integer.parseInt(pluginIdStr);
            consumeMappedAlert(pluginId, alertName, isActionableAlert(params));
        } catch (NumberFormatException e) {
            LOGGER.warn("Could not parse plugin ID from alert event: {}", pluginIdStr);
        }

        recordDetectedTechnology(alertName);
    }

    void consumeAlert(Alert alert) {
        if (alert == null) {
            return;
        }
        consumeMappedAlert(alert.getPluginId(), alert.getName(), isActionableAlert(alert));
        recordDetectedTechnology(alert.getName());
    }

    private void consumeMappedAlert(int pluginId, String alertName, boolean actionable) {
        var wstgIds = mappingManager.getWstgIdsForPlugin(pluginId);
        if (actionable && !wstgIds.isEmpty()) {
            LOGGER.debug("Alert pluginId={} triggers WSTG tests: {}", pluginId, wstgIds);
            checklistManager.triggerTests(wstgIds);
        }
    }

    private void recordDetectedTechnology(String alertName) {
        if (alertName == null || alertName.isBlank()) {
            return;
        }
        String detectedTechnology = detectTechnology(alertName);
        if (detectedTechnology != null) {
            LOGGER.debug("Alert name '{}' matches technology '{}'.", alertName, detectedTechnology);
            checklistManager.addDetectedTechnology(detectedTechnology);
        }
    }

    private static boolean isActionableAlert(Map<String, String> params) {
        String risk = firstPresent(params, AlertEventPublisher.RISK_STRING, "riskString", "risk");
        if (isInformationalOrFalsePositive(risk)) {
            return false;
        }

        String confidence =
                firstPresent(params, "confidenceString", "confidence", "confidenceName", "conf");
        if (isExplicitLowConfidence(confidence) && !hasConcreteEvidence(params)) {
            return false;
        }
        return true;
    }

    private static boolean isActionableAlert(Alert alert) {
        if (alert == null) {
            return false;
        }
        if (alert.getRisk() == Alert.RISK_INFO
                || alert.getConfidence() == Alert.CONFIDENCE_FALSE_POSITIVE) {
            return false;
        }
        if (alert.getConfidence() == Alert.CONFIDENCE_LOW
                && isBlank(alert.getEvidence())
                && isBlank(alert.getParam())
                && isBlank(alert.getAttack())) {
            return false;
        }
        return true;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static boolean isInformationalOrFalsePositive(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return normalized.equals("informational")
                || normalized.equals("info")
                || normalized.equals("false positive")
                || normalized.equals("false_positive");
    }

    private static boolean isExplicitLowConfidence(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return normalized.equals("low") || normalized.equals("1");
    }

    private static boolean hasConcreteEvidence(Map<String, String> params) {
        return hasValue(params, "evidence")
                || hasValue(params, "param")
                || hasValue(params, "attack")
                || hasValue(params, "requestHeader")
                || hasValue(params, "responseHeader");
    }

    private static boolean hasValue(Map<String, String> params, String key) {
        String value = params.get(key);
        return value != null && !value.isBlank();
    }

    private static String firstPresent(Map<String, String> params, String... keys) {
        for (String key : keys) {
            String value = params.get(key);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return "";
    }

    private String detectTechnology(String alertName) {
        String normalizedAlertName = alertName.toLowerCase(Locale.ROOT);
        return mappingManager.getAllTechnologies().stream()
                .sorted(Comparator.comparingInt(String::length).reversed())
                .filter(technology -> containsTechnology(normalizedAlertName, technology))
                .findFirst()
                .orElse(null);
    }

    private static boolean containsTechnology(String alertName, String technology) {
        if (alertName.equals(technology) || alertName.contains(": " + technology)) {
            return true;
        }
        String bounded = alertName.replaceAll("[^a-z0-9.+#-]+", " ");
        for (String token : bounded.split(" ")) {
            if (token.equals(technology)) {
                return true;
            }
        }
        return false;
    }
}
