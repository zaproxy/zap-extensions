/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.addon.requester.internal.tab.close;

import java.awt.GridBagConstraints;
import java.awt.event.ActionListener;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.requester.ExtensionRequester;

public class CloseTabPanel extends JPanel {

    private static final long serialVersionUID = 1L;
    private static final Icon CLOSE_TAB_GREY_ICON =
            ExtensionRequester.createIcon("fugue/cross-small-grey.png");
    private static final Icon CLOSE_TAB_RED_ICON =
            ExtensionRequester.createIcon("fugue/cross-small-red.png");

    private final JLabel titleLabel;

    public CloseTabPanel(String tabName, ActionListener closeButtonAction) {
        super();
        this.setOpaque(false);
        titleLabel = new JLabel(tabName);

        GridBagConstraints gridConstraints = new GridBagConstraints();
        gridConstraints.gridx = 0;
        gridConstraints.gridy = 0;
        gridConstraints.weightx = 1;

        this.add(titleLabel, gridConstraints);

        gridConstraints.gridx++;
        gridConstraints.weightx = 0;

        JButton closeButton = createCloseButton(closeButtonAction);
        this.add(closeButton, gridConstraints);
    }

    @Override
    public void setName(String name) {
        super.setName(name);
        if (titleLabel != null) {
            titleLabel.setText(name);
        }
    }

    @Override
    public String getName() {
        if (titleLabel != null) {
            return titleLabel.getText();
        }
        return super.getName();
    }

    private static JButton createCloseButton(ActionListener closeButtonAction) {
        JButton closeButton = new JButton();
        closeButton.setOpaque(false);

        // Configure icon and rollover icon for button
        closeButton.setRolloverIcon(CLOSE_TAB_RED_ICON);
        closeButton.setRolloverEnabled(true);
        closeButton.setContentAreaFilled(false);
        closeButton.setToolTipText(Constant.messages.getString("all.button.close"));
        closeButton.setIcon(CLOSE_TAB_GREY_ICON);
        // Set a border only on the left side so the button doesn't make the tab too big
        closeButton.setBorder(new EmptyBorder(0, 6, 0, 0));
        // This is needed to Macs for some reason
        closeButton.setBorderPainted(false);

        // Make sure the button can't get focus, otherwise it looks funny
        closeButton.setFocusable(false);

        // Add action listener
        closeButton.addActionListener(closeButtonAction);
        return closeButton;
    }
}
