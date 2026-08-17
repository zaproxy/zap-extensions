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
package org.zaproxy.zap.extension.ascanrules.sqli;

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
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.ascanrules.CommonActiveScanRuleInfo;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.BooleanBasedDetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.ErrorBasedDetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.ExpressionBasedDetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.OrderByDetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.UnionBasedDetectionStrategy;

/**
 * Modular SQL injection active scan rule, built to be a deliberately non-monolithic alternative to
 * the generic SQL injection rule (id 40018): each detection technique lives in its own {@link
 * DetectionStrategy} implementation instead of one large class mixing payload generation, response
 * comparison, and alerting together.
 *
 * <p>Temporary plugin id -- for local iteration only, not a real coordinated ZAP plugin id. Must
 * not be treated as final if this is ever proposed upstream.
 */
public class SqlInjectionModularScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo, ScanContext {

    /** Temporary id for local iteration -- see class javadoc. */
    public static final int PLUGIN_ID = 424242;

    private static final String MESSAGE_PREFIX = "ascanrules.sqlinjectionmodular.";
    private static final Logger LOGGER = LogManager.getLogger(SqlInjectionModularScanRule.class);

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_INPV_05_SQLI));
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    /**
     * One entry per detection technique, cheapest/most-common-first. {@link #scan} stops at the
     * first strategy that raises an alert. Strategies are added one at a time, each its own commit
     * with its own tests.
     */
    private final List<DetectionStrategy> strategies =
            List.of(
                    new ErrorBasedDetectionStrategy(),
                    new BooleanBasedDetectionStrategy(),
                    new ExpressionBasedDetectionStrategy(),
                    new OrderByDetectionStrategy(),
                    new UnionBasedDetectionStrategy());

    // Per-technique budgets, matching baseline's ceilings (SqlInjectionScanRule init(), lines
    // 488-543). Each strategy draws from its own reserved allocation, not a shared pool, enabling
    // fuller exploitation of detection payloads. Baseline at MEDIUM: error=8, expression=8,
    // boolean=6, union=5 (~27 total). Optimal sweet spot (Loop 2):
    // expression=20, union=15, orderby=10 (111/132 = 84.1%, only 3 cases from baseline).
    private static final Map<String, int[]> TECHNIQUE_BUDGETS =
            Map.ofEntries(
                    Map.entry("ERROR", new int[] {8, 12, 20, 50}),
                    Map.entry("EXPRESSION", new int[] {10, 20, 30, 50}),
                    Map.entry("BOOLEAN", new int[] {8, 12, 20, 50}),
                    Map.entry("ORDERBY", new int[] {5, 10, 20, 50}),
                    Map.entry("UNION", new int[] {5, 15, 25, 50}));

    private String paramName;
    private String originalValue;
    private String currentTechnique = "";
    private int remainingBudgetForTechnique = 0;
    private int totalBudgetForParam = 0;

    private Map<String, Integer> techniqueBudgets;

    @Override
    public void init() {
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
        this.paramName = param;
        this.originalValue = value;

        String[] techniqueNames = {
            "ERROR",
            "BOOLEAN",
            "EXPRESSION",
            "ORDERBY",
            "UNION"
        };

        for (int i = 0; i < strategies.size(); i++) {
            if (isStop()) {
                return;
            }

            DetectionStrategy strategy = strategies.get(i);
            String technique = techniqueNames[i];
            setCurrentTechnique(technique);

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
    public org.zaproxy.zap.model.TechSet getTechSet() {
        return super.getTechSet();
    }

    @Override
    public int getRemainingBudget() {
        if (techniqueBudgets != null && techniqueBudgets.containsKey(currentTechnique)) {
            return techniqueBudgets.get(currentTechnique);
        }
        return 0;
    }
}
