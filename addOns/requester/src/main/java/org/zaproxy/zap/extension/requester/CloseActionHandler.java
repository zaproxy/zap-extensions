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
package org.zaproxy.zap.extension.requester;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JTabbedPane;

public class CloseActionHandler implements ActionListener {

    private String tabName;

    private NumberedRenamableTabbedPane numberedTabbedPane;

    public CloseActionHandler(NumberedRenamableTabbedPane numberedTabbedPane, String tabName) {
        this.numberedTabbedPane = numberedTabbedPane;
        this.tabName = tabName;
    }

    public NumberedRenamableTabbedPane getNumberedTabbedPane() {
        return numberedTabbedPane;
    }

    public String getTabName() {
        return tabName;
    }

    @Override
    public void actionPerformed(ActionEvent evt) {

        JTabbedPane ntp = getNumberedTabbedPane();

        int index = ntp.indexOfTab(getTabName());
        if (index >= 0) {
            if (ntp.getTabCount() > 2 && index == ntp.getTabCount() - 2) {
                ntp.setSelectedIndex(index - 1);
            }
            ManualHttpRequestEditorPanel currentEditor =
                    (ManualHttpRequestEditorPanel) ntp.getComponentAt(index);
            currentEditor.beforeClose();
            currentEditor.saveConfig();
            ntp.removeTabAt(index);
        }
    }
}
