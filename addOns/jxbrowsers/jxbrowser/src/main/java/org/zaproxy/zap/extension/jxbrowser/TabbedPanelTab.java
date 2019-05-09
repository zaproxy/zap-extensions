/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.jxbrowser;

import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.Constant;

public class TabbedPanelTab extends JPanel {

    private static final Icon CLOSE_TAB_GREY_ICON =
            new ImageIcon(
                    TabbedPanelTab.class.getResource("/resource/icon/fugue/cross-small-grey.png"));
    private static final Icon CLOSE_TAB_RED_ICON =
            new ImageIcon(
                    TabbedPanelTab.class.getResource("/resource/icon/fugue/cross-small-red.png"));

    private static final long serialVersionUID = 1L;

    private JButton btnClose = new JButton();
    private JLabel lblTitle = new JLabel();

    public TabbedPanelTab(
            final ZapTabbedPanel parent,
            String title,
            Icon icon,
            final Component component,
            boolean hideable) {
        super(new FlowLayout(FlowLayout.CENTER, 0, 0));

        this.setOpaque(false);

        if (component.getName() == null) {
            component.setName(title);
        }

        // Add a JLabel with title and the left-side tab icon
        this.setTitle(title);
        lblTitle.setIcon(icon);

        this.add(lblTitle);

        if (hideable) {
            // Create a JButton for the close tab button
            btnClose.setOpaque(false);

            // Configure icon and rollover icon for button
            btnClose.setRolloverIcon(CLOSE_TAB_RED_ICON);
            btnClose.setRolloverEnabled(true);
            btnClose.setContentAreaFilled(false);
            btnClose.setToolTipText(Constant.messages.getString("all.button.close"));
            btnClose.setIcon(CLOSE_TAB_GREY_ICON);
            // Set a border only on the left side so the button doesn't make the tab too big
            btnClose.setBorder(new EmptyBorder(0, 6, 0, 0));
            // This is needed to Macs for some reason
            btnClose.setBorderPainted(false);

            // Make sure the button can't get focus, otherwise it looks funny
            btnClose.setFocusable(false);

            // All close buttons start off hidden and disabled - they are enabled when the tab is
            // selected
            btnClose.setEnabled(false);
            btnClose.setVisible(false);

            // Add the listener that removes the tab
            ActionListener closeListener =
                    new ActionListener() {

                        @Override
                        public void actionPerformed(ActionEvent e) {
                            parent.remove(component);
                        }
                    };
            btnClose.addActionListener(closeListener);

            // Only include the close button is the tab is hideable
            this.add(btnClose);
        }
    }

    @Override
    public void setEnabled(boolean enabled) {
        btnClose.setEnabled(enabled);
        btnClose.setVisible(enabled);
    }

    public void setTitle(String title) {
        lblTitle.setText(title);
    }
}
