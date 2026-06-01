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

import java.awt.GridBagConstraints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.llm.ExtensionLlm;

@SuppressWarnings("serial")
public class LlmCloseTabPanel extends JPanel {

    private static final long serialVersionUID = 1L;
    private static final Icon CLOSE_TAB_GREY_ICON =
            ExtensionLlm.createIcon("/resource/icon/fugue/cross-small-grey.png");
    private static final Icon CLOSE_TAB_RED_ICON =
            ExtensionLlm.createIcon("/resource/icon/fugue/cross-small-red.png");

    private final JLabel lblTitle;
    private final String tag;

    public LlmCloseTabPanel(String tabName, LlmNumberedRenamableTabbedPane tabbedPane, String tag) {
        super();
        this.setOpaque(false);
        lblTitle = new JLabel(tabName);
        this.tag = tag;
        JButton btnClose = new JButton();
        btnClose.setOpaque(false);

        btnClose.setRolloverIcon(CLOSE_TAB_RED_ICON);
        btnClose.setRolloverEnabled(true);
        btnClose.setContentAreaFilled(false);
        btnClose.setToolTipText(Constant.messages.getString("all.button.close"));
        btnClose.setIcon(CLOSE_TAB_GREY_ICON);
        btnClose.setBorder(new EmptyBorder(0, 6, 0, 0));
        btnClose.setBorderPainted(false);
        btnClose.setFocusable(false);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1;

        this.add(lblTitle, gbc);

        gbc.gridx++;
        gbc.weightx = 0;
        this.add(btnClose, gbc);

        btnClose.addActionListener(new LlmCloseActionHandler(tabbedPane, tag, tabName));
    }

    @Override
    public void setName(String name) {
        super.setName(name);
        if (lblTitle != null) {
            lblTitle.setText(name);
        }
    }

    @Override
    public String getName() {
        if (lblTitle != null) {
            return lblTitle.getText();
        }
        return super.getName();
    }

    public String getTag() {
        return this.tag;
    }

    private class LlmCloseActionHandler implements ActionListener {

        private final String tag;
        private final String tabName;
        private final LlmNumberedRenamableTabbedPane tabbedPane;

        public LlmCloseActionHandler(
                LlmNumberedRenamableTabbedPane tabbedPane, String tag, String tabName) {
            this.tabbedPane = tabbedPane;
            this.tag = tag;
            this.tabName = tabName;
        }

        @Override
        public void actionPerformed(ActionEvent evt) {
            JTabbedPane ntp = tabbedPane;

            int index = ntp.indexOfTab(tabName);
            if (index >= 0) {
                if (ntp.getTabCount() > 2 && index == ntp.getTabCount() - 2) {
                    ntp.setSelectedIndex(index - 1);
                }
                ntp.removeTabAt(index);
            }
            if (tag != null) {
                tabbedPane.unregisterTag(tag);
            }
        }
    }
}
