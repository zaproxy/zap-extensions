package org.zaproxy.zap.extension.foxhound.alerts;

import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class FoxhoundCsrfCheck implements FoxhoundVulnerabilityCheck {

    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_9");
    private static final Map<String, String> ALERT_TAGS;
    private static final Set<String> SINKS;
    private static final Set<String> SOURCES;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A07_XSS,
                                CommonAlertTag.WSTG_V42_CLNT_01_DOM_XSS));

        ALERT_TAGS = Collections.unmodifiableMap(alertTags);

        SINKS = Set.of(
                "navigator.sendBeacon(body)",
                "navigator.sendBeacon(url)",
                "fetch.body",
                "fetch.url",
                "XMLHttpRequest.open(password)",
                "XMLHttpRequest.open(url)",
                "XMLHttpRequest.open(username)",
                "XMLHttpRequest.send",
                "XMLHttpRequest.setRequestHeader(name)",
                "XMLHttpRequest.setRequestHeader(value)",
                "WebSocket",
                "WebSocket.send",
                "EventSource",
                "window.open",
                "window.postMessage",
                "location.assign",
                "location.hash",
                "location.host",
                "location.href",
                "location.pathname",
                "location.port",
                "location.protocol",
                "location.replace",
                "location.search"
        );

        SOURCES = Set.of(
                "location.hash",
                "location.href",
                "location.pathname",
                "location.search",
                "window.name",
                "document.referrer",
                "document.baseURI",
                "document.documentURI"
        );

    }

    @Override
    public String getVulnName() {
        return VULN.getName();
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getConfidence() {
        return Alert.CONFIDENCE_MEDIUM;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public String getDescription() {
        return VULN.getDescription();
    }

    @Override
    public String getSolution() {
        return VULN.getSolution();
    }

    @Override
    public String getReferences() {
        return VULN.getReferencesAsString();
    }

    @Override
    public int getCwe() {
        return 352;
    }

    @Override
    public int getWascId() {
        return VULN.getWascId();
    }

    @Override
    public boolean shouldAlert(TaintInfo taint) {

        if (!SINKS.contains(taint.getSink().getOperation())) {
            return false;
        }

        Set<String> sources = new HashSet<>();
        for (TaintOperation op : taint.getSources()) {
            sources.add(op.getOperation());
        }

        return !Collections.disjoint(sources, SOURCES);
    }

}
