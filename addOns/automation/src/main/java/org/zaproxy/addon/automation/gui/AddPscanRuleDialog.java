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
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.automation.jobs.PassiveScanConfigJob;
import org.zaproxy.addon.automation.jobs.PassiveScanConfigJob.Rule;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class AddPscanRuleDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.addrule.title";
    private static final String RULE_PARAM = "automation.dialog.addrule.rule";
    private static final String THREHOLD_PARAM = "automation.dialog.addrule.threshold";

    private PassiveScanConfigJob.Rule rule;
    private int tableIndex;
    private PscanRulesTableModel model;
    private Map<String, PluginPassiveScanner> nameToPlugin = new HashMap<>();

    public AddPscanRuleDialog(PscanRulesTableModel model) {
        this(model, null, -1);
    }

    public AddPscanRuleDialog(
            PscanRulesTableModel model, PassiveScanConfigJob.Rule rule, int tableIndex) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(400, 200));
        this.rule = rule;
        this.model = model;
        this.tableIndex = tableIndex;

        String thresholdName = "";
        if (rule != null) {
            thresholdName = JobUtils.thresholdToI18n(rule.getThreshold());
        }

        List<PluginPassiveScanner> allRules = model.getAllScanRules();

        List<String> allNames =
                allRules.stream()
                        .map(PluginPassiveScanner::getName)
                        .sorted()
                        .collect(Collectors.toList());
        // Remove any rules already set
        allNames.removeAll(
                model.getRules().stream().map(Rule::getName).collect(Collectors.toList()));
        nameToPlugin =
                allRules.stream()
                        .collect(
                                Collectors.toMap(
                                        PluginPassiveScanner::getName, Function.identity()));

        if (rule == null) {
            this.addComboField(RULE_PARAM, allNames, "");
        } else {
            this.addReadOnlyField(RULE_PARAM, rule.getName(), false);
        }

        List<String> allthresholds = new ArrayList<>();

        for (AlertThreshold at : AlertThreshold.values()) {
            if (AlertThreshold.DEFAULT.equals(at)) {
                continue;
            }
            allthresholds.add(JobUtils.thresholdToI18n(at.name()));
        }

        this.addComboField(THREHOLD_PARAM, allthresholds, thresholdName);

        this.addPadding();
    }

    @Override
    public void save() {
        if (rule == null) {
            rule = new Rule();
            PluginPassiveScanner plugin = this.nameToPlugin.get(this.getStringValue(RULE_PARAM));
            rule.setId(plugin.getPluginId());
            rule.setName(plugin.getName());
            rule.setThreshold(JobUtils.i18nToThreshold(this.getStringValue(THREHOLD_PARAM)));
            this.model.add(rule);
        } else {
            rule.setThreshold(JobUtils.i18nToStrength(this.getStringValue(THREHOLD_PARAM)));
            this.model.update(tableIndex, rule);
        }
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
