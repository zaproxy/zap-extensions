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
package org.zaproxy.addon.commonlib.ui;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.CommonlibParam;
import org.zaproxy.zap.extension.alert.PopupMenuItemAlert;

/**
 * A right-click menu item for alerts that generates a prompt the user can paste into an LLM to ask
 * it to fix the vulnerability. The prompt is copied to the system clipboard.
 *
 * <p>The prompt text is intentionally written in English rather than translated, as LLMs generally
 * perform better with English input.
 */
@SuppressWarnings("serial")
public class GenerateFixPromptMenu extends PopupMenuItemAlert {

    private static final long serialVersionUID = 1L;

    // Prompt text is not i18n - LLMs handle English better than other languages.
    private static final String INTRO =
            "A security scanner (ZAP by Checkmarx) has found a vulnerability in the application you are"
                    + " working on. Please identify where in the codebase this vulnerability exists"
                    + " and provide a fix.";
    private static final String SYSTEMIC_NOTE =
            "Note: This vulnerability appears to occur across the application - there may be"
                    + " multiple instances that all need to be fixed.";
    private static final String CLOSING =
            "Please identify where in the codebase this vulnerability exists and provide a fix.";

    private final CommonlibParam param;

    public GenerateFixPromptMenu(CommonlibParam param) {
        super(Constant.messages.getString("commonlib.alert.generatefixprompt.menu"), false);
        this.param = param;
    }

    @Override
    public void performAction(Alert alert) {
        String prompt = buildPrompt(alert);
        Toolkit.getDefaultToolkit()
                .getSystemClipboard()
                .setContents(new StringSelection(prompt), null);

        if (param.isShowFixPromptCopiedDialog()) {
            JCheckBox doNotShowAgain =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "commonlib.alert.generatefixprompt.donotshowagain"));
            JOptionPane.showMessageDialog(
                    View.getSingleton().getMainFrame(),
                    new Object[] {
                        Constant.messages.getString("commonlib.alert.generatefixprompt.copied"),
                        " ",
                        doNotShowAgain
                    },
                    Constant.messages.getString("commonlib.alert.generatefixprompt.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            param.setShowFixPromptCopiedDialog(!doNotShowAgain.isSelected());
        }
    }

    static String buildPrompt(Alert alert) {
        StringBuilder sb = new StringBuilder();

        sb.append(INTRO);
        sb.append("\n\n");

        boolean systemic =
                alert.getTags() != null
                        && alert.getTags().containsKey(CommonAlertTag.SYSTEMIC.getTag());
        if (systemic) {
            sb.append(SYSTEMIC_NOTE);
            sb.append("\n\n");
        }

        sb.append("## Vulnerability\n\n");

        appendField(sb, "Name", alert.getName());

        int risk = alert.getRisk();
        if (risk >= 0 && risk < Alert.MSG_RISK.length) {
            appendField(sb, "Risk", Alert.MSG_RISK[risk]);
        }

        int confidence = alert.getConfidence();
        if (confidence >= 0 && confidence < Alert.MSG_CONFIDENCE.length) {
            appendField(sb, "Confidence", Alert.MSG_CONFIDENCE[confidence]);
        }

        appendField(sb, "URL", alert.getUri());
        appendField(sb, "Method", alert.getMethod());
        appendField(sb, "Parameter", alert.getParam());
        appendField(sb, "Attack", alert.getAttack());
        appendField(sb, "Evidence", alert.getEvidence());

        appendSection(sb, "Description", alert.getDescription());
        appendSection(sb, "Solution", alert.getSolution());
        appendSection(sb, "References", alert.getReference());
        appendSection(sb, "Other Information", alert.getOtherInfo());

        sb.append("\n").append(CLOSING);

        return sb.toString();
    }

    private static void appendField(StringBuilder sb, String label, String value) {
        if (StringUtils.isNotBlank(value)) {
            sb.append("**").append(label).append("**: ").append(value).append("\n");
        }
    }

    private static void appendSection(StringBuilder sb, String heading, String value) {
        if (StringUtils.isNotBlank(value)) {
            sb.append("\n## ").append(heading).append("\n\n");
            sb.append(value).append("\n");
        }
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
