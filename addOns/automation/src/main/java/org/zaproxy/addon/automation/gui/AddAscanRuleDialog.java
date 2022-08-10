/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation.gui;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.apache.commons.configuration.ConfigurationException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.ActiveScanJob.Rule;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class AddAscanRuleDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.addrule.title";
    private static final String RULE_PARAM = "automation.dialog.addrule.rule";
    private static final String THREHOLD_PARAM = "automation.dialog.addrule.threshold";
    private static final String STRENGTH_PARAM = "automation.dialog.addrule.strength";

    private ActiveScanJob.Rule rule;
    private int tableIndex;
    private AscanRulesTableModel model;
    private Map<String, Plugin> nameToPlugin = new HashMap<>();
    private List<Plugin> allRules = null;

    public AddAscanRuleDialog(AscanRulesTableModel model) throws ConfigurationException {
        this(model, null, -1);
    }

    public AddAscanRuleDialog(AscanRulesTableModel model, ActiveScanJob.Rule rule, int tableIndex)
            throws ConfigurationException {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(300, 150));
        this.rule = rule;
        this.model = model;
        this.tableIndex = tableIndex;

        String thresholdName = "";
        if (rule != null) {
            thresholdName = JobUtils.thresholdToI18n(rule.getThreshold());
        }

        String strengthName = "";
        if (rule != null) {
            strengthName = JobUtils.strengthToI18n(rule.getStrength());
        }

        allRules = model.getAllScanRules();

        List<String> allNames =
                allRules.stream().map(Plugin::getName).sorted().collect(Collectors.toList());
        // Remove any rules already set
        allNames.removeAll(
                model.getRules().stream().map(Rule::getName).collect(Collectors.toList()));
        nameToPlugin =
                allRules.stream().collect(Collectors.toMap(Plugin::getName, Function.identity()));

        if (rule == null) {
            this.addComboField(RULE_PARAM, allNames, "");
        } else {
            this.addReadOnlyField(RULE_PARAM, rule.getName(), false);
        }

        List<String> allthresholds = new ArrayList<>();

        for (AlertThreshold at : AlertThreshold.values()) {
            allthresholds.add(JobUtils.thresholdToI18n(at.name()));
        }

        this.addComboField(THREHOLD_PARAM, allthresholds, thresholdName);

        List<String> allstrengths = new ArrayList<>();

        for (AttackStrength at : AttackStrength.values()) {
            allstrengths.add(JobUtils.strengthToI18n(at.name()));
        }

        this.addComboField(STRENGTH_PARAM, allstrengths, strengthName);

        this.addPadding();
    }

    @Override
    public void save() {
        if (rule == null) {
            rule = new Rule();
            Plugin plugin = this.nameToPlugin.get(this.getStringValue(RULE_PARAM));
            rule.setId(plugin.getId());
            rule.setName(plugin.getName());
            rule.setThreshold(JobUtils.i18nToThreshold(this.getStringValue(THREHOLD_PARAM)));
            rule.setStrength(JobUtils.i18nToStrength(this.getStringValue(STRENGTH_PARAM)));
            this.model.add(rule);
        } else {
            rule.setThreshold(JobUtils.i18nToThreshold(this.getStringValue(THREHOLD_PARAM)));
            rule.setStrength(JobUtils.i18nToStrength(this.getStringValue(STRENGTH_PARAM)));
            this.model.update(tableIndex, rule);
        }
    }

    @Override
    public String validateFields() {
        if (JobUtils.i18nToThreshold(this.getStringValue(THREHOLD_PARAM)).equals("default")
                && JobUtils.i18nToStrength(this.getStringValue(STRENGTH_PARAM)).equals("default")) {
            return Constant.messages.getString("automation.dialog.addrule.error.defaults");
        }
        return null;
    }
}
