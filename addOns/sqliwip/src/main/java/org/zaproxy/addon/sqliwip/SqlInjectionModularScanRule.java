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
package org.zaproxy.addon.sqliwip;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.AbstractPlugin.AlertBuilder;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Modular SQL injection active scan rule: each detection technique lives in its own {@link
 * DetectionStrategy} instead of one large class mixing payload generation, response comparison and
 * alerting together.
 *
 * <p>Temporary plugin id, not a real coordinated ZAP plugin id. Must not be treated as final.
 */
public class SqlInjectionModularScanRule extends AbstractAppParamPlugin implements ScanContext {

    /** Temporary id, see class javadoc. */
    public static final int PLUGIN_ID = 424242;

    private static final String MESSAGE_PREFIX = "sqliwip.";
    private static final Logger LOGGER = LogManager.getLogger(SqlInjectionModularScanRule.class);

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.API_2023_API10_UNSAFE_CONSUMPTION,
                                CommonAlertTag.OWASP_2025_A05_INJECTION,
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_INPV_05_SQLI,
                                CommonAlertTag.HIPAA,
                                CommonAlertTag.PCI_DSS));
        alertTags.put(PolicyTag.API.getTag(), "");
        alertTags.put(PolicyTag.DEV_CICD.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_CICD.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    /**
     * The detection techniques, most common first. {@link #scan} stops at the first one that raises
     * an alert. Empty for now: techniques are added one at a time, each with its own tests.
     */
    private final List<DetectionStrategy> strategies = List.of();

    private String paramName;
    private String originalValue;
    private String currentTechnique = "";
    private ParameterContext parameterContext;
    private HttpMessage cachedBaseline;
    private HttpMessage cachedControl;
    private HttpMessage cachedRepeat;

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    public String getHelpLink() {
        return "https://www.zaproxy.org/docs/desktop/addons/active-scan-rules/#id-40018";
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 89;
    }

    @Override
    public int getWascId() {
        return 19;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        if (strategies.isEmpty()) {
            // Nothing to run, so don't spend requests on the baseline and control.
            return;
        }

        this.paramName = param;
        this.originalValue = value;

        try {
            // One baseline and one control per parameter, shared by every technique.
            cachedBaseline = getNewMsg();
            setParameter(cachedBaseline, param, value);
            super.sendAndReceive(cachedBaseline);
            parameterContext = SqliContextAnalyzer.analyze(value, cachedBaseline);
            // A replay is only meaningful for this parameter's own baseline.
            cachedRepeat = null;

            cachedControl = getNewMsg();
            setParameter(cachedControl, param, value + CONTROL_SUFFIX);
            super.sendAndReceive(cachedControl);
        } catch (IOException e) {
            LOGGER.debug(
                    "Failed to initialize parameter context for parameter [{}]: {}",
                    param,
                    e.getMessage());
            return;
        }

        for (DetectionStrategy strategy : strategies) {
            if (isStop()) {
                return;
            }

            try {
                if (strategy.detect(this)) {
                    return;
                }
            } catch (IOException e) {
                LOGGER.debug(
                        "{} failed for parameter [{}]: {}",
                        strategy.getClass().getSimpleName(),
                        param,
                        e.getMessage());
            }
        }
    }

    private static boolean isDb(Tech tech) {
        Tech parent = tech.getParent();
        if (parent == null) {
            return false;
        }
        return Tech.Db.equals(parent) || isDb(parent);
    }

    @Override
    public boolean targets(TechSet technologies) {
        if (technologies.includes(Tech.Db)) {
            return true;
        }

        for (Tech tech : technologies.getIncludeTech()) {
            // No-SQL techs are children of Tech.Db but not SQL.
            if (!Tech.MongoDB.equals(tech) && !Tech.CouchDB.equals(tech) && isDb(tech)) {
                return true;
            }
        }
        return false;
    }

    // -- ScanContext: delegation to the protected AbstractPlugin/AbstractAppParamPlugin
    // primitives that strategies, being in another package, can't call directly. --

    @Override
    public HttpMessage getBaseMessage() {
        return getBaseMsg();
    }

    @Override
    public HttpMessage newMessage() {
        return getNewMsg();
    }

    @Override
    public void setParam(HttpMessage message, String value) {
        setParameter(message, paramName, value);
    }

    @Override
    public void sendAndReceive(HttpMessage message) throws IOException {
        super.sendAndReceive(message);
    }

    @Override
    public void setCurrentTechnique(String technique) {
        currentTechnique = technique;
    }

    @Override
    public boolean isStopped() {
        return isStop();
    }

    @Override
    public AlertBuilder newAlert() {
        return super.newAlert();
    }

    @Override
    public String getParamName() {
        return paramName;
    }

    @Override
    public String getOriginalValue() {
        return originalValue;
    }

    @Override
    public TechSet getTechSet() {
        return super.getTechSet();
    }

    @Override
    public AlertThreshold getAlertThreshold() {
        return super.getAlertThreshold();
    }

    @Override
    public int getRemainingBudget() {
        // Per-technique budgets arrive with the first technique.
        return 0;
    }

    @Override
    public ParameterContext getParameterContext() {
        return parameterContext;
    }

    @Override
    public HttpMessage getCachedBaseline() {
        return cachedBaseline;
    }

    @Override
    public HttpMessage getCachedControl() {
        return cachedControl;
    }

    @Override
    public HttpMessage getRepeatedBaseline() throws IOException {
        if (cachedRepeat == null) {
            cachedRepeat = getNewMsg();
            setParameter(cachedRepeat, paramName, originalValue);
            sendAndReceive(cachedRepeat);
        }
        return cachedRepeat;
    }

    @Override
    public void recordBaselineMatch() {
        // Metrics arrive with the first technique.
    }

    @Override
    public void recordSuppressedDifferential() {
        // Metrics arrive with the first technique.
    }
}
