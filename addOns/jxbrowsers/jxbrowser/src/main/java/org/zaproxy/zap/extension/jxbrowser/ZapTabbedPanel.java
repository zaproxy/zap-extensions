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
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JTabbedPane;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import org.zaproxy.zap.utils.DisplayUtils;

public class ZapTabbedPanel extends JTabbedPane {

    private static final long serialVersionUID = 1L;

    public ZapTabbedPanel() {

        this.addChangeListener(
                new ChangeListener() {

                    @Override
                    public void stateChanged(ChangeEvent e) {
                        setCloseButtonStates();
                    }
                });
    }

    public void addTab(
            String title, Icon icon, final Component component, boolean hideable, int index) {
        if (index == -1 || index > this.getTabCount()) {
            index = this.getTabCount();
        }
        if (icon instanceof ImageIcon) {
            icon = DisplayUtils.getScaledIcon((ImageIcon) icon);
        }

        super.insertTab(title, icon, component, component.getName(), index);

        int pos = this.indexOfComponent(component);
        // Now assign the component for the tab

        this.setTabComponentAt(pos, new TabbedPanelTab(this, title, icon, component, hideable));

        if ((index == 0 || getTabCount() == 1) && indexOfComponent(component) != -1) {
            // Its now the first one, give it focus
            setSelectedComponent(component);
        }
    }

    @Override
    public void remove(Component component) {
        int pos = this.indexOfComponent(component);
        if (pos == -1) {
            return;
        }

        if (pos == getTabCount() - 2) {
            setSelectedIndex(getTabCount() - 3);
        }
        super.remove(component);
        setCloseButtonStates();
    }

    private void setCloseButtonStates() {
        if (this.getTabCount() == 0) {
            return;
        }

        // Hide all 'close' buttons except for the selected tab
        if (this.getTabCount() <= 2) {
            // just one tab and maybe the Plus one, so dont allow the first one to be closed
            Component tabCom = this.getTabComponentAt(0);
            if (tabCom != null && tabCom instanceof TabbedPanelTab) {
                TabbedPanelTab jp = (TabbedPanelTab) tabCom;
                jp.setEnabled(false);
            }
        } else {
            for (int i = 0; i < this.getTabCount(); i++) {
                Component tabCom = this.getTabComponentAt(i);
                if (tabCom != null && tabCom instanceof TabbedPanelTab) {
                    TabbedPanelTab jp = (TabbedPanelTab) tabCom;
                    jp.setEnabled(i == getSelectedIndex());
                }
            }
        }
    }
}
