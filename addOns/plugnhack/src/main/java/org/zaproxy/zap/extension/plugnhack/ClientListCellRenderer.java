/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.plugnhack;

import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.ListCellRenderer;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.LayoutHelper;

public class ClientListCellRenderer extends JPanel implements ListCellRenderer<MonitoredPage> {

    private static final long serialVersionUID = 1L;
    private JLabel id = null;
    private JLabel url = null;

    /** This is the default constructor */
    public ClientListCellRenderer() {
        super();

        initialize();
    }

    /** This method initializes this */
    private void initialize() {
        id = new JLabel();
        id.setText(" ");
        id.setBackground(java.awt.SystemColor.text);
        id.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        id.setPreferredSize(new java.awt.Dimension(100, 15));
        id.setMinimumSize(new java.awt.Dimension(80, 15));
        id.setFont(FontUtils.getFont(FontUtils.Size.standard));
        id.setOpaque(true);

        url = new JLabel();
        url.setText(" ");
        url.setBackground(java.awt.SystemColor.text);
        url.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        url.setPreferredSize(new java.awt.Dimension(320, 15));
        url.setMinimumSize(new java.awt.Dimension(320, 15));
        url.setFont(FontUtils.getFont(FontUtils.Size.standard));
        url.setOpaque(true);

        this.setLayout(new GridBagLayout());
        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            this.setSize(328, 11);
        }
        this.setFont(FontUtils.getFont(FontUtils.Size.standard));

        this.add(id, LayoutHelper.getGBC(1, 0, 1, 0.0D, new Insets(0, 0, 0, 0)));
        this.add(url, LayoutHelper.getGBC(2, 0, 1, 1.0D, new Insets(0, 0, 0, 0)));
    }

    @Override
    public Component getListCellRendererComponent(
            JList<? extends MonitoredPage> list,
            MonitoredPage page,
            int index,
            boolean isSelected,
            boolean cellHasFocus) {

        id.setText(page.getId());
        try {
            url.setText(page.getURI().toString());
        } catch (Exception e) {
            // Ignore
        }

        if (page.isActive()) {
            id.setIcon(DisplayUtils.getScaledIcon(ExtensionPlugNHack.CLIENT_ACTIVE_ICON));
        } else {
            id.setIcon(DisplayUtils.getScaledIcon(ExtensionPlugNHack.CLIENT_INACTIVE_ICON));
        }
        url.setIcon(DisplayUtils.getScaledIcon(page.getIcon()));

        if (isSelected) {
            id.setBackground(list.getSelectionBackground());
            id.setForeground(list.getSelectionForeground());
            url.setBackground(list.getSelectionBackground());
            url.setForeground(list.getSelectionForeground());

        } else {
            Color darker = new Color(list.getBackground().getRGB() & 0xFFECECEC);
            id.setBackground(darker);
            id.setForeground(list.getForeground());
            url.setBackground(list.getBackground());
            url.setForeground(list.getForeground());
        }
        setEnabled(list.isEnabled());
        setFont(list.getFont());
        return this;
    }
}
