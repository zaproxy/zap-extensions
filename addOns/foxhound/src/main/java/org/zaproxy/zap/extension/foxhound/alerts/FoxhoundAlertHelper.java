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
package org.zaproxy.zap.extension.foxhound.alerts;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.foxhound.FoxhoundEventPublisher;
import org.zaproxy.zap.extension.foxhound.db.TaintInfoStore;
import org.zaproxy.zap.extension.foxhound.taint.HttpMessageFinder;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintRange;

public class FoxhoundAlertHelper implements EventConsumer {

    private static final Logger LOGGER = LogManager.getLogger(FoxhoundAlertHelper.class);
    private TaintInfoStore store;

    private static Set<FoxhoundVulnerabilityCheck> CHECKS =
            Set.of(
                    new FoxhoundXssCheck(),
                    new FoxhoundTaintInfoCheck(),
                    new FoxhoundStoredXssCheck(),
                    new FoxhoundCsrfCheck());

    private ExtensionAlert extensionAlert = null;

    public FoxhoundAlertHelper(TaintInfoStore store) {
        this.store = store;
        ZAP.getEventBus()
                .registerConsumer(this, FoxhoundEventPublisher.getPublisher().getPublisherName());
    }

    private ExtensionAlert getExtensionAlert() {
        if (extensionAlert == null) {
            extensionAlert =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        }
        return extensionAlert;
    }

    private static String getOtherInfo(TaintInfo taint) {
        StringBuilder sb = new StringBuilder();
        if (taint != null) {
            sb.append(Constant.messages.getString("foxhound.alert.sinkToSource")).append(" ");
            sb.append(taint.getSourceSinkLabel());
            sb.append(System.lineSeparator());
            sb.append(
                    String.format(
                            Constant.messages.getString("foxhound.alert.otherInfo"),
                            taint.getStr()));
            sb.append(System.lineSeparator());
            sb.append(System.lineSeparator());

            sb.append(Constant.messages.getString("foxhound.alert.detailedSinkInfo"));
            sb.append(System.lineSeparator());
            // Work out the maxiumum number of digits we need so the ranges are all aligned
            List<TaintRange> ranges = taint.getTaintRanges();
            int highestRangeEnd = ranges.isEmpty() ? 0 : ranges.get(ranges.size() - 1).getEnd();
            String fmtString =
                    String.format(
                            "[%%0%sd, %%0%sd)",
                            String.valueOf(highestRangeEnd).length(),
                            String.valueOf(highestRangeEnd).length());
            for (TaintRange range : ranges) {
                sb.append(String.format(fmtString, range.getBegin(), range.getEnd()));
                sb.append(" \"");
                sb.append(range.getStr());
                sb.append("\" ");
                sb.append(Constant.messages.getString("foxhound.alert.sinkToSource")).append(" ");
                sb.append(range.getSourceSinkLabel());
                sb.append(System.lineSeparator());
            }
        }
        return sb.toString();
    }

    protected static String getUrl(TaintInfo taint) {
        return taint.getSink().getLocation().getFilename();
    }

    public void raiseAlerts(TaintInfo taint) {
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Raising alerts for taint flow: {}", taint);
        }
        for (Alert alert : createAlerts(taint)) {
            // Only raise an alert if we have found a message, otherwise an exception is thrown
            if (alert.getMessage() != null) {
                // Use null so the alertFound uses the historyRef from the alert
                getExtensionAlert().alertFound(alert, null);
            }
        }
    }

    protected static Alert.Builder getAlertBuilderFromCheck(FoxhoundVulnerabilityCheck check) {
        Alert.Builder alertBuilder = Alert.builder();
        if (check != null) {
            alertBuilder
                    .setPluginId(check.getScanId())
                    .setName(check.getVulnName())
                    .setRisk(check.getRisk())
                    .setDescription(check.getDescription())
                    .setSolution(check.getSolution())
                    .setReference(check.getReferences())
                    .setCweId(check.getCwe())
                    .setWascId(check.getWascId())
                    .setTags(check.getAlertTags())
                    .setConfidence(check.getConfidence());
        }

        return alertBuilder;
    }

    protected static List<Alert> createAlerts(TaintInfo taint) {
        List<Alert> alerts = new ArrayList<>();

        String url = getUrl(taint);
        HttpMessage msg = HttpMessageFinder.findHttpMessage(url);

        String evidence =
                (msg == null)
                        ? ""
                        : taint.getSink()
                                .getLocation()
                                .getCodeForEvidence(msg.getResponseBody().toString());
        String otherInfo = getOtherInfo(taint);
        for (FoxhoundVulnerabilityCheck check : CHECKS) {
            if (check.shouldAlert(taint)) {
                Alert.Builder alertBuilder =
                        getAlertBuilderFromCheck(check)
                                .setUri(url)
                                .setOtherInfo(otherInfo)
                                .setEvidence(evidence)
                                .setParam(taint.getSink().getOperation());
                if (msg != null) {
                    alertBuilder.setMessage(msg);
                    alertBuilder.setHistoryRef(msg.getHistoryRef());
                }

                alerts.add(alertBuilder.build());
            }
        }
        return alerts;
    }

    @Override
    public void eventReceived(Event event) {
        if (event.getEventType().equals(FoxhoundEventPublisher.TAINT_INFO_CREATED)) {
            String jobIdStr = event.getParameters().get(FoxhoundEventPublisher.JOB_ID);
            if (jobIdStr == null) {
                return;
            }
            int jobId;
            try {
                jobId = Integer.parseInt(jobIdStr);
            } catch (NumberFormatException e) {
                return;
            }
            TaintInfo taintInfo = this.store.getTaintInfo(jobId);
            if (taintInfo != null) {
                raiseAlerts(taintInfo);
            }
        }
    }

    public static List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        for (FoxhoundVulnerabilityCheck check : CHECKS) {
            alerts.add(getAlertBuilderFromCheck(check).build());
        }
        return alerts;
    }
}
