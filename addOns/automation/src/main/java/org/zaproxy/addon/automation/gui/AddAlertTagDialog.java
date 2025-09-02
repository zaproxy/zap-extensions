/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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

import static java.util.function.Predicate.not;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class AddAlertTagDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.ascanpolicyalerttags.addalerttag";

    private static final String ALERT_TAG_PARAM = "automation.dialog.ascanpolicyalerttags.alerttag";

    private String alertTagPattern;
    private AlertTagsTableModel alertTagsTableModel;
    private int tableIndex;

    public AddAlertTagDialog(
            ActiveScanPolicyDialog parent,
            AlertTagsTableModel alertTagsTableModel,
            int tableIndex) {
        super(parent, TITLE, DisplayUtils.getScaledDimension(400, 100));
        this.alertTagsTableModel = alertTagsTableModel;
        this.alertTagPattern =
                tableIndex != -1
                        ? alertTagsTableModel.getAlertTagPatterns().get(tableIndex).pattern()
                        : null;
        this.tableIndex = tableIndex;

        List<String> allActiveAlertTags =
                new ScanPolicy()
                        .getPluginFactory().getAllPlugin().stream()
                                .map(Plugin::getAlertTags)
                                .filter(Objects::nonNull)
                                .filter(not(Map::isEmpty))
                                .map(Map::keySet)
                                .flatMap(Set::stream)
                                .distinct()
                                .sorted()
                                .toList();
        this.addComboField(ALERT_TAG_PARAM, allActiveAlertTags, alertTagPattern, true);
        this.addPadding();
    }

    @Override
    public void save() {
        this.alertTagPattern = this.getStringValue(ALERT_TAG_PARAM).trim();
        if (this.tableIndex == -1) {
            alertTagsTableModel.add(Pattern.compile(this.alertTagPattern));
        } else {
            alertTagsTableModel.update(this.tableIndex, Pattern.compile(this.alertTagPattern));
        }
    }

    @Override
    public String validateFields() {
        String str = this.getStringValue(ALERT_TAG_PARAM).trim();
        if (!JobUtils.containsVars(str)) {
            // Can only validate strings that dont contain env vars
            try {
                Pattern.compile(str);
            } catch (Exception e) {
                return Constant.messages.getString(
                        "automation.dialog.ascanpolicyalerttags.error.badregex", str);
            }
        }
        return null;
    }
}
