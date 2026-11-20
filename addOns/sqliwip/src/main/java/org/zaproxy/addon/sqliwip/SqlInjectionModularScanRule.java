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
 * Modular SQL injection active scan rule, built to be a deliberately non-monolithic alternative to
 * the generic SQL injection rule (id 40018): each detection technique lives in its own {@link
 * DetectionStrategy} implementation instead of one large class mixing payload generation, response
 * comparison, and alerting together.
 *
 * <p>Temporary plugin id -- for local iteration only, not a real coordinated ZAP plugin id. Must
 * not be treated as final if this is ever proposed upstream.
 *
 * <p>Foundation step: the detection-strategy list is deliberately empty here. Each technique is
 * ported in its own follow-up change, one at a time, with its own tests.
 */
public class SqlInjectionModularScanRule extends AbstractAppParamPlugin implements ScanContext {

    /** Temporary id for local iteration -- see class javadoc. */
    public static final int PLUGIN_ID = 424242;

    /** Baseline rule 40018's plugin id, whose help anchor {@link #getHelpLink()} reuses. */
    private static final int BASELINE_RULE_ID = 40018;

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
     * One entry per detection technique, cheapest/most-common-first. {@link #scan} stops at the
     * first strategy that raises an alert. Strategies are added one at a time, each its own commit
     * with its own tests -- empty for now, see the class javadoc.
     */
    private final List<DetectionStrategy> strategies = List.of();

    /**
     * Per-technique budgets, indexed by attack strength (LOW, MEDIUM, HIGH, INSANE). Empty for now,
     * alongside {@link #strategies}; each technique's allocation arrives with that technique.
     */
    private static final Map<String, int[]> TECHNIQUE_BUDGETS = Map.of();

    private String paramName;
    private String originalValue;
    private String currentTechnique = "";

    private Map<String, Integer> techniqueBudgets;
    private ParameterContext parameterContext;
    private HttpMessage cachedBaseline;
    private HttpMessage cachedControl;

    @Override
    public void init() {
        initBudgets();
    }

    private void initBudgets() {
        int strengthIndex =
                switch (getAttackStrength()) {
                    case LOW -> 0;
                    case DEFAULT, MEDIUM -> 1;
                    case HIGH -> 2;
                    case INSANE -> 3;
                };

        techniqueBudgets = new HashMap<>();
        for (Map.Entry<String, int[]> entry : TECHNIQUE_BUDGETS.entrySet()) {
            techniqueBudgets.put(entry.getKey(), entry.getValue()[strengthIndex]);
        }
    }

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

    /**
     * Points at rule 40018's help anchor, since that is where this rule ends up. Not an
     * {@code @Override}: this add-on has no dependency on ascanrules, so {@code
     * CommonActiveScanRuleInfo} (which declares the default this would otherwise override) isn't
     * visible here.
     */
    public String getHelpLink() {
        return "https://www.zaproxy.org/docs/desktop/addons/active-scan-rules/#id-"
                + BASELINE_RULE_ID;
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
            // Nothing to run yet, so don't spend requests on a baseline and control no strategy
            // would use.
            return;
        }

        this.paramName = param;
        this.originalValue = value;

        try {
            // One baseline per parameter, fetched here and shared by every technique: a technique
            // fetching its own copy only re-buys the same page, once per technique that compares
            // against a baseline.
            cachedBaseline = getNewMsg();
            setParameter(cachedBaseline, param, value);
            super.sendAndReceive(cachedBaseline);
            parameterContext = SqliContextAnalyzer.analyze(value, cachedBaseline);

            cachedControl = getNewMsg();
            setParameter(cachedControl, param, value + CONTROL_SUFFIX);
            super.sendAndReceive(cachedControl);
        } catch (IOException e) {
            LOGGER.debug(
                    "Failed to initialize parameter context for parameter [{}]: {}",
                    param,
                    e.getMessage());
            // Without this parameter's own baseline and control no technique has anything to
            // compare against.
            return;
        }

        // 40018 reinitialises its per-technique counts for every parameter (SqlInjectionScanRule
        // scan(), "reinitialise the count for each type of request, for each parameter"), so a
        // multi-parameter request (page + username + password) starts each parameter with a full
        // budget rather than spending earlier parameters' requests from later ones' allowance.
        initBudgets();

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

    /**
     * Returns true if the tech is a child of Tech.Db.
     *
     * @param tech the tech to check
     * @return true if the tech is a child of Tech.Db
     */
    private static boolean isDb(Tech tech) {
        Tech parent = tech.getParent();
        if (parent == null) {
            return false;
        }
        if (Tech.Db.equals(parent)) {
            return true;
        }
        return isDb(parent);
    }

    /**
     * Returns true if the tech is an SQL related tech. Explicitly excludes known no-sql techs,
     * mirroring baseline rule 40018's targeting.
     *
     * @param tech the tech to check
     * @return true if the supplied tech is SQL related
     */
    private static boolean isSqlDb(Tech tech) {
        if (Tech.MongoDB.equals(tech) || Tech.CouchDB.equals(tech)) {
            return false;
        }
        return isDb(tech);
    }

    @Override
    public boolean targets(TechSet technologies) {
        if (technologies.includes(Tech.Db)) {
            return true;
        }

        for (Tech tech : technologies.getIncludeTech()) {
            if (isSqlDb(tech)) {
                return true;
            }
        }
        return false;
    }

    // -- ScanContext: thin delegation to the protected AbstractPlugin/AbstractAppParamPlugin
    // primitives that strategies (living in a different package) can't call directly. --

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
        if (techniqueBudgets != null && techniqueBudgets.containsKey(currentTechnique)) {
            int current = techniqueBudgets.get(currentTechnique);
            if (current > 0) {
                techniqueBudgets.put(currentTechnique, current - 1);
            }
        }
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
        if (techniqueBudgets != null && techniqueBudgets.containsKey(currentTechnique)) {
            return techniqueBudgets.get(currentTechnique);
        }
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
}
