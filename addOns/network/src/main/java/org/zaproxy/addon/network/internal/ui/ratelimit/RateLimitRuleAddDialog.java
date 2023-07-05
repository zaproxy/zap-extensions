/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ui.ratelimit;

import java.awt.Window;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitOptions;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitRule;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class RateLimitRuleAddDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String FIRST_TAB = "network.ui.ratelimit.tab.rule";

    private static final String[] ADV_TAB_LABELS = {FIRST_TAB};

    protected static final String DESC_FIELD = "network.ui.ratelimit.label.desc";
    protected static final String MATCH_STR_FIELD = "network.ui.ratelimit.label.matchstr";
    protected static final String REGEX_FIELD = "network.ui.ratelimit.label.regex";
    protected static final String REQUESTS_PER_SECOND_FIELD =
            "network.ui.ratelimit.label.requestspersecond";
    protected static final String GROUP_BY = "network.ui.ratelimit.label.groupby";
    protected static final String ENABLE_FIELD = "network.ui.ratelimit.label.enable";

    private RateLimitOptions rateLimitOptions;
    private RateLimitRule rule;
    private final OptionsRateLimitTableModel rateLimitModel;

    public RateLimitRuleAddDialog(
            Window owner,
            String title,
            RateLimitOptions rateLimitOptions,
            OptionsRateLimitTableModel rateLimitModel) {
        super(owner, title, DisplayUtils.getScaledDimension(500, 350), ADV_TAB_LABELS, true);
        this.rateLimitOptions = rateLimitOptions;
        this.rateLimitModel = rateLimitModel;
        initFields();
    }

    private void initFields() {

        this.removeAllFields();
        this.addTextField(0, DESC_FIELD, "");
        this.addTextField(0, MATCH_STR_FIELD, "");
        this.addCheckBoxField(0, REGEX_FIELD, false);

        this.addNumberField(0, REQUESTS_PER_SECOND_FIELD, 1, Integer.MAX_VALUE, 1);
        List<String> groupByValues = getGroupByValues();
        this.addComboField(0, GROUP_BY, groupByValues, groupByValues.get(0));
        this.addCheckBoxField(0, ENABLE_FIELD, false);
        this.addPadding(0);

        // Set before adding the listener so we don't get in a loop
        this.setRuleInternal(rule);
    }

    private List<String> getGroupByValues() {
        List<String> list = new ArrayList<>();
        for (RateLimitRule.GroupBy e : RateLimitRule.GroupBy.values()) {
            list.add(e.getLabel());
        }
        return list;
    }

    public RateLimitRule getRule() {
        return rule;
    }

    public void setRule(RateLimitRule rule) {
        initFields();
        this.setRuleInternal(rule);
    }

    public OptionsRateLimitTableModel getRateLimitModel() {
        return this.rateLimitModel;
    }

    public RateLimitOptions getRateLimitParam() {
        return rateLimitOptions;
    }

    public void setRateLimitParam(RateLimitOptions rateLimitOptions) {
        this.rateLimitOptions = rateLimitOptions;
    }

    private void setRuleInternal(RateLimitRule rule) {
        this.rule = rule;
        if (rule != null) {
            this.setFieldValue(DESC_FIELD, rule.getDescription());
            this.setFieldValue(MATCH_STR_FIELD, rule.getMatchString());
            this.setFieldValue(REGEX_FIELD, rule.isMatchRegex());
            this.setFieldValue(REQUESTS_PER_SECOND_FIELD, rule.getRequestsPerSecond());
            this.setFieldValue(GROUP_BY, rule.getGroupBy().getLabel());
            this.setFieldValue(ENABLE_FIELD, rule.isEnabled());
        }
    }

    @Override
    public void cancelPressed() {
        super.cancelPressed();
        this.rule = null;
    }

    @Override
    public void save() {
        saveImpl();
    }

    private RateLimitRule.GroupBy getSelectedGroupBy() {
        String selectedStr = this.getStringValue(GROUP_BY);
        for (RateLimitRule.GroupBy e : RateLimitRule.GroupBy.values()) {
            if (selectedStr.equals(e.getLabel())) {
                return e;
            }
        }
        return RateLimitRule.GroupBy.RULE;
    }

    public void saveImpl() {
        rule =
                new RateLimitRule(
                        this.getStringValue(DESC_FIELD),
                        this.getStringValue(MATCH_STR_FIELD),
                        this.getBoolValue(REGEX_FIELD),
                        this.getIntValue(REQUESTS_PER_SECOND_FIELD),
                        getSelectedGroupBy(),
                        this.getBoolValue(ENABLE_FIELD));
    }

    protected String checkIfUnique() {
        if (this.rateLimitModel.containsRule(this.getStringValue(DESC_FIELD))) {
            return Constant.messages.getString("network.ui.ratelimit.add.warning.existdesc");
        }
        return null;
    }

    @Override
    public String validateFields() {
        if (this.isEmptyField(DESC_FIELD)) {
            return Constant.messages.getString("network.ui.ratelimit.add.warning.nodesc");
        }
        if (this.isEmptyField(MATCH_STR_FIELD)) {
            return Constant.messages.getString("network.ui.ratelimit.add.warning.nomatch");
        }
        if (Boolean.TRUE.equals(this.getBoolValue(REGEX_FIELD))) {
            // Check the regex is valid
            try {
                Pattern.compile(this.getStringValue(MATCH_STR_FIELD));
            } catch (PatternSyntaxException e) {
                return Constant.messages.getString("network.ui.ratelimit.add.warning.badregex");
            }
        }
        return checkIfUnique();
    }

    public void clear() {
        this.rule = null;
        this.setFieldValue(DESC_FIELD, "");
        this.setFieldValue(MATCH_STR_FIELD, "");
        this.setFieldValue(REQUESTS_PER_SECOND_FIELD, 1);
        this.setFieldValue(GROUP_BY, RateLimitRule.GroupBy.RULE.getLabel());
        this.setFieldValue(ENABLE_FIELD, false);
    }
}
