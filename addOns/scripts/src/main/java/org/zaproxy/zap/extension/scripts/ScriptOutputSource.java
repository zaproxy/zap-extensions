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
package org.zaproxy.zap.extension.scripts;

import java.util.List;
import java.util.Map;
import javax.swing.AbstractButton;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import lombok.EqualsAndHashCode;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.ui.TabbedOutputPanel;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.OutputSource;
import org.zaproxy.zap.view.ZapToggleButton;

@EqualsAndHashCode(callSuper = false)
public class ScriptOutputSource extends OutputSource {

    private static final ImageIcon CLEAR_ON_RUN_DISABLED_ICON =
            getImageIcon(
                    "/org/zaproxy/zap/extension/scripts/resources/icons/broom-play-disabled.png");
    private static final ImageIcon CLEAR_ON_RUN_ENABLED_ICON =
            getImageIcon(
                    "/org/zaproxy/zap/extension/scripts/resources/icons/broom-play-enabled.png");

    private final ScriptWrapper script;
    private final String name;
    private boolean clearOnRun;

    public ScriptOutputSource(ScriptWrapper script) {
        this.script = script;
        this.name = script.getName();
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of(
                TabbedOutputPanel.ATTRIBUTE_ICON,
                getIcon(),
                TabbedOutputPanel.ATTRIBUTE_ADDITIONAL_BUTTONS,
                getAdditionalButtons());
    }

    boolean isClearOnRun() {
        return clearOnRun;
    }

    private Icon getIcon() {
        return script.getType().getIcon();
    }

    private List<AbstractButton> getAdditionalButtons() {
        var clearOnRunButton = new ZapToggleButton();
        clearOnRunButton.setName("clearOnRunButton");
        clearOnRunButton.setToolTipText(
                Constant.messages.getString("scripts.output.clearOnRun.button.disabled.toolTip"));
        clearOnRunButton.setSelectedToolTipText(
                Constant.messages.getString("scripts.output.clearOnRun.button.enabled.toolTip"));
        clearOnRunButton.setIcon(DisplayUtils.getScaledIcon(CLEAR_ON_RUN_DISABLED_ICON));
        clearOnRunButton.setSelectedIcon(DisplayUtils.getScaledIcon(CLEAR_ON_RUN_ENABLED_ICON));
        clearOnRunButton.addActionListener(e -> clearOnRun = clearOnRunButton.isSelected());
        return List.of(clearOnRunButton);
    }

    private static ImageIcon getImageIcon(String resourceName) {
        return DisplayUtils.getScaledIcon(ScriptOutputSource.class.getResource(resourceName));
    }
}
