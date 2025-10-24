package org.zaproxy.zap.extension.foxhound.alerts;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintLocation;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.model.StructuralNode;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class FoxhoundAlertHelper {

    private static final Logger LOGGER = LogManager.getLogger(FoxhoundAlertHelper.class);

    private static final Set<FoxhoundVulnerabilityCheck> CHECKS;

    static {
        Set<FoxhoundVulnerabilityCheck> checks = new HashSet<>();
        checks.add(new FoxhoundXssCheck());
        checks.add(new FoxhoundTaintInfoCheck());
        CHECKS = Collections.unmodifiableSet(checks);
    }

    private TaintInfo taint;
    private HttpMessage msg;
    private ExtensionAlert extensionAlert =
            Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);

    public FoxhoundAlertHelper(TaintInfo taint) {
        this.taint = taint;
        this.msg = findHttpMessage(getUrl());
    }

    private static HttpMessage findHttpMessage(String url) {
        String[] methods = { "GET", "POST" };
        Model model = Model.getSingleton();

        HistoryReference ref = null;
        HttpMessage msg = null;

        try {
            URI uri = new URI(url, true);
            uri.setFragment("");

            // Try multiple methods as we don't know it from the URL
            for (String method : methods) {
                StructuralNode node = SessionStructure.find(model, uri, "GET", null);

                if (node != null) {
                    ref = node.getHistoryReference();
                    if (ref != null) {
                        msg = ref.getHttpMessage();
                        break;
                    }
                }
            }

        } catch (URIException | DatabaseException | HttpMalformedHeaderException e) {
            LOGGER.warn("Exception getting HttpMessage for URL: {} ({})", url, e.getMessage());
        }

        return msg;
    }

    private static String getEvidenceFromBody(HttpMessage msg, TaintOperation sink) {
        String evidence = null;
        if (sink != null) {
            if (msg != null) {
                TaintLocation sinkLocation = sink.getLocation();
                String sinkBody = msg.getResponseBody().toString();
                String[] lines = sinkBody.split("\\r?\\n");

                // Line from TaintLocation starts at 1, so adjust for array access
                int line = sinkLocation.getLine() - 1;
                if (line >= 0 && line < lines.length) {
                    // Get the rest of the statement, either to the end of the line or to the next semicolon
                    evidence = lines[line].substring(sinkLocation.getPos() - 1);
                    String[] lineParts = evidence.split(";");
                    if (lineParts.length > 0) {
                        evidence = lineParts[0];
                    }
                }
            } else {
                evidence = sink.getOperation();
            }
        }
        return evidence;
    }

    private String getOtherInfo() {
        StringBuilder sb = new StringBuilder();
        if (taint != null) {
            sb.append(Constant.messages.getString("foxhound.alert.otherInfo"))
                    .append(" ")
                    .append(taint.getStr());
        }
        return sb.toString();
    }

    protected String getUrl() {
        return taint.getSink().getLocation().getFilename();
    }

    public void raiseAlerts() {
        String url = getUrl();
        String evidence = getEvidenceFromBody(msg, getTaint().getSink());
        String otherInfo = getOtherInfo();
        LOGGER.info("Raising alerts for taint flow: " + getTaint());

        if (msg != null) {
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
                            .setAttack("Attack")
                            .setOtherInfo(otherInfo)
                            .setEvidence(evidence)
                            .setMessage(msg)
                            .setHistoryRef(msg.getHistoryRef());

                    // Use null so the alertFound uses the historyRef from the alert
                    extensionAlert.alertFound(alertBuilder.build(), null);
                }
            }
        }
    }

    public TaintInfo getTaint() {
        return taint;
    }

    public void setTaint(TaintInfo taint) {
        this.taint = taint;
    }

    public HttpMessage getMsg() {
        return msg;
    }

    public void setMsg(HttpMessage msg) {
        this.msg = msg;
    }
}
