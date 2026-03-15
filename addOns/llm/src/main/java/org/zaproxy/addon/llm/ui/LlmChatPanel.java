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
package org.zaproxy.addon.llm.ui;

import java.awt.GridLayout;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.DisplayUtils;

@SuppressWarnings("serial")
public class LlmChatPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    private LlmNumberedRenamableTabbedPane tabbedPane;

    public LlmChatPanel(ExtensionLlm extension) {
        setName(Constant.messages.getString("llm.chat.panel.title"));
        setIcon(
                DisplayUtils.getScaledIcon(
                        getClass().getResource("/org/zaproxy/addon/llm/resources/agent.png")));
        setLayout(new GridLayout(1, 1));

        tabbedPane = new LlmNumberedRenamableTabbedPane(extension);
        add(tabbedPane);

        ExtensionHelp.enableHelpKey(this, "addon.llm.chat");
    }

    public void appendToInput(String str) {
        appendToInput(str, false);
    }

    public void appendToInput(String str, boolean grabFocus) {
        LlmChatTabPanel selectedPanel = tabbedPane.getSelectedChatPanel();
        if (selectedPanel != null) {
            selectedPanel.appendToInput(str, grabFocus);
        }
        if (grabFocus) {
            setTabFocus();
        }
    }

    public void appendUntrustedDataToInput(Map<String, Object> payload, boolean grabFocus) {
        appendUntrustedDataToInput(tabbedPane.getSelectedChatPanel(), payload, grabFocus);
    }

    public void appendUntrustedDataToInput(
            String tag, String tabName, Map<String, Object> payload, boolean grabFocus) {
        appendUntrustedDataToInput(tabbedPane.getTaggedTab(tag, tabName), payload, grabFocus);
    }

    private void appendUntrustedDataToInput(
            LlmChatTabPanel panel, Map<String, Object> payload, boolean grabFocus) {
        if (panel != null) {
            panel.appendUntrustedDataToInput(payload, grabFocus);
        }
        if (grabFocus) {
            tabbedPane.setSelectedComponent(panel);
            setTabFocus();
        }
    }

    public static void appendFormattedMsg(StringBuilder sb, String prefix, String msg) {
        if (StringUtils.isNotEmpty(msg)) {
            sb.append(Constant.messages.getString("llm.chat.append.gen.format", prefix, msg))
                    .append("\n");
        }
    }

    public LlmNumberedRenamableTabbedPane getTabbedPane() {
        return tabbedPane;
    }
}
