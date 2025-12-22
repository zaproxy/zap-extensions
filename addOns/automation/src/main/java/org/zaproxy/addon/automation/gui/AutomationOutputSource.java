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
package org.zaproxy.addon.automation.gui;

import java.util.Map;
import javax.swing.ImageIcon;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.commonlib.ui.TabbedOutputPanel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.OutputSource;

public class AutomationOutputSource extends OutputSource {

    private static final ImageIcon ROBOT_ICON =
            getImageIcon(ExtensionAutomation.RESOURCES_DIR + "robot.png");
    private final String name;

    public AutomationOutputSource(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of(TabbedOutputPanel.ATTRIBUTE_ICON, ROBOT_ICON);
    }

    private static ImageIcon getImageIcon(String resourceName) {
        return DisplayUtils.getScaledIcon(AutomationOutputSource.class.getResource(resourceName));
    }
}
