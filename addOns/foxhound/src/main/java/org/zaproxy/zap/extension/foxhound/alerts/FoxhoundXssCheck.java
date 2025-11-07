package org.zaproxy.zap.extension.foxhound.alerts;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;
import org.zaproxy.zap.extension.foxhound.taint.SinkTag;
import org.zaproxy.zap.extension.foxhound.taint.SourceTag;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class FoxhoundXssCheck implements FoxhoundVulnerabilityCheck {

    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_8");
    private static final Map<String, String> ALERT_TAGS;
    private static final Set<String> XSS_SINKS;
    private static final Set<String> XSS_SOURCES;
    private static final Logger LOGGER = LogManager.getLogger(FoxhoundXssCheck.class);

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A07_XSS,
                                CommonAlertTag.WSTG_V42_CLNT_01_DOM_XSS));
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);

        XSS_SINKS = FoxhoundConstants.getSinkNamesWithTag(SinkTag.XSS);
        XSS_SOURCES = FoxhoundConstants.getSourceNamesWithTags(List.of(SourceTag.URL, SourceTag.INPUT));

    }

    @Override
    public String getVulnName() {
        return VULN.getName();
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getConfidence() {
        return Alert.CONFIDENCE_HIGH;
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
        return 79;
    }

    @Override
    public int getWascId() {
        return VULN.getWascId();
    }

    @Override
    public boolean shouldAlert(TaintInfo taint) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sinks: Need one of: {} got: {}", XSS_SINKS, taint.getSink().getOperation());
            LOGGER.debug("Sources: Need one of: {} got: {}", XSS_SOURCES, taint.getSources().stream().map(TaintOperation::getOperation).toList());
        }

        if (!XSS_SINKS.contains(taint.getSink().getOperation())) {
            return false;
        }

        Set<String> sources = new HashSet<>();
        for (TaintOperation op : taint.getSources()) {
            sources.add(op.getOperation());
        }

        return !Collections.disjoint(sources, XSS_SOURCES);
    }

}
