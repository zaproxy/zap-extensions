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
package org.zaproxy.zap.extension.foxhound.ui;

import java.io.Serial;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundSeleniumProfile;

public class FoxhoundLaunchButton extends JButton {

    @Serial private static final long serialVersionUID = 1L;

    public FoxhoundLaunchButton(FoxhoundSeleniumProfile profile) {
        this.setIcon(createIcon(FoxhoundConstants.FOXHOUND_16));
        this.setToolTipText(Constant.messages.getString("foxhound.ui.launchTooltip"));
        this.addActionListener(
                e -> {
                    if (!profile.launchFoxhound()) {
                        JOptionPane.showMessageDialog(
                                View.getSingleton().getMainFrame(),
                                Constant.messages.getString("foxhound.ui.notfound"));
                    }
                });
    }

    private ImageIcon createIcon(String path) {
        return new ImageIcon(FoxhoundLaunchButton.class.getResource(path));
    }
}
