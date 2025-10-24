package org.zaproxy.zap.extension.foxhound.alerts;

import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;

import java.util.Map;

public class FoxhoundTaintInfoCheck implements FoxhoundVulnerabilityCheck {

    @Override
    public Map<String, String> getAlertTags() {
        return Map.of();
    }

    @Override
    public String getVulnName() {
        return "Client-Side Data Flow";
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public int getConfidence() {
        return Alert.CONFIDENCE_HIGH;
    }

    @Override
    public String getDescription() {
        return "";
    }

    @Override
    public String getSolution() {
        return "";
    }

    @Override
    public String getReferences() {
        return "";
    }

    @Override
    public int getCwe() {
        return 0;
    }

    @Override
    public int getWascId() {
        return 0;
    }

    @Override
    public boolean shouldAlert(TaintInfo taint) {
        return true;
    }
}
