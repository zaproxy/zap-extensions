/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart;

import javax.swing.BoxLayout;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.utils.ZapLabel;

public class QuickStartHelper {

    public static JPanel getHorizontalPanel() {
        JPanel panel = new QuickStartBackgroundPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        return panel;
    }

    public static ZapLabel getWrappedLabel(String key) {
        ZapLabel label = new QuickStartLabel(Constant.messages.getString(key));
        label.setLineWrap(true);
        label.setWrapStyleWord(true);
        return label;
    }

    private static class QuickStartLabel extends ZapLabel {
        private static final long serialVersionUID = 1L;

        public QuickStartLabel(String text) {
            super(text);
            setBackground(QuickStartBackgroundPanel.getBackgroundColor());
        }

        @Override
        public void updateUI() {
            super.updateUI();
            setBackground(QuickStartBackgroundPanel.getBackgroundColor(true));
        }
    }

    public static void raiseOptionsChangedEvent() {
        Control.getSingleton()
                .getExtensionLoader()
                .optionsChangedAllPlugin(Model.getSingleton().getOptionsParam());
    }
}
