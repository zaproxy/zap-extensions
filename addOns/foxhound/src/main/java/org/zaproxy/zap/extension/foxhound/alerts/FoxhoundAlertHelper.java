package org.zaproxy.zap.extension.foxhound.alerts;

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
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;
import org.zaproxy.zap.extension.foxhound.taint.TaintRange;

import java.util.List;
import java.util.Set;

public class FoxhoundAlertHelper implements EventConsumer {

    private static final Logger LOGGER = LogManager.getLogger(FoxhoundAlertHelper.class);
    private TaintInfoStore store;

    private static final Set<FoxhoundVulnerabilityCheck> CHECKS = Set.of(
            new FoxhoundXssCheck(),
            new FoxhoundTaintInfoCheck(),
            new FoxhoundStoredXssCheck(),
            new FoxhoundCsrfCheck()
    );

    private final ExtensionAlert extensionAlert =
            Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);

    public FoxhoundAlertHelper(TaintInfoStore store) {
        this.store = store;
        ZAP.getEventBus()
                .registerConsumer(this, FoxhoundEventPublisher.getPublisher().getPublisherName());
    }

    private String getOtherInfo(TaintInfo taint) {
        StringBuilder sb = new StringBuilder();
        if (taint != null) {
            sb.append(Constant.messages.getString("foxhound.alert.sinkToSource")).append(" ");
            sb.append(taint.getSourceSinkLabel());
            sb.append(System.lineSeparator());
            sb.append(
                String.format(
                    Constant.messages.getString("foxhound.alert.otherInfo"),
                    taint.getStr()
                )
            );
            sb.append(System.lineSeparator());
            sb.append(System.lineSeparator());

            sb.append(Constant.messages.getString("foxhound.alert.detailedSinkInfo"));
            sb.append(System.lineSeparator());
            // Work out the maxiumum number of digits we need so the ranges are all aligned
            List<TaintRange> ranges = taint.getTaintRanges();
            int highestRangeEnd =  ranges.isEmpty() ? 0 : ranges.get(ranges.size() - 1).getEnd();
            String fmtString = String.format("[%%0%sd, %%0%sd)",
                    String.valueOf(highestRangeEnd).length(), String.valueOf(highestRangeEnd).length());
            for (TaintRange range : ranges) {
                sb.append(
                        String.format(fmtString,
                                range.getBegin(),
                                range.getEnd()
                        ));
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

    protected String getUrl(TaintInfo taint) {
        return taint.getSink().getLocation().getFilename();
    }

    public void raiseAlerts(TaintInfo taint) {
        String url = getUrl(taint);
        HttpMessage msg = HttpMessageFinder.findHttpMessage(url);
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Raising alerts for taint flow: {}", taint);
        }

        if (msg != null) {
            String evidence = taint.getSink().getLocation().getCodeForEvidence(msg.getResponseBody().toString());
            String otherInfo = getOtherInfo(taint);
            for (FoxhoundVulnerabilityCheck check : CHECKS) {
                if (check.shouldAlert(taint)) {
                    Alert.Builder alertBuilder = Alert.builder()
                            .setPluginId(40099)
                            .setName(check.getVulnName())
                            .setRisk(check.getRisk())
                            .setDescription(check.getDescription())
                            .setSolution(check.getSolution())
                            .setReference(check.getReferences())
                            .setCweId(check.getCwe())
                            .setWascId(check.getWascId())
                            .setTags(check.getAlertTags())
                            .setConfidence(check.getConfidence())
                            .setUri(url)
                            .setOtherInfo(otherInfo)
                            .setEvidence(evidence)
                            .setParam(taint.getSink().getOperation())  // "param" should be one of the URL parameters
                            .setMessage(msg)
                            .setHistoryRef(msg.getHistoryRef());

                    // Use null so the alertFound uses the historyRef from the alert
                    extensionAlert.alertFound(alertBuilder.build(), null);
                }
            }
        }
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
}
