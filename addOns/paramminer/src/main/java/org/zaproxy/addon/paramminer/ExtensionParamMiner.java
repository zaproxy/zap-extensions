/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.paramminer;

import javax.swing.ImageIcon;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.paramminer.gui.ParamMinerPanel;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionParamMiner extends ExtensionAdaptor {

    public static final String NAME = "ExtensionParamMiner";
    protected static final String PREFIX = "paramminer";
    private static final String RESOURCES = "resources";
    private static ImageIcon icon;

    private ParamMinerPanel paramMinerPanel;
    private ZapMenuItem menu;
    private ParamMinerAPI api;

    public ExtensionParamMiner() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    public static ImageIcon getIcon() {
        if (icon == null) {
            icon = new ImageIcon(ExtensionParamMiner.class.getResource(RESOURCES + "/pickaxe.png"));
        }
        return icon;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        this.api = new ParamMinerAPI();
        extensionHook.addApiImplementor(this.api);

        if (getView() != null) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenu());
            extensionHook.getHookView().addStatusPanel(getParamMinerPanel());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
    }

    private ParamMinerPanel getParamMinerPanel() {
        if (paramMinerPanel == null) {
            paramMinerPanel = new ParamMinerPanel(this);
        }
        return paramMinerPanel;
    }

    private ZapMenuItem getMenu() {
        if (menu == null) {
            menu = new ZapMenuItem(PREFIX + ".topmenu.tools.title");

            menu.addActionListener(
                    e -> {
                        View.getSingleton()
                                .showMessageDialog(
                                        Constant.messages.getString(PREFIX + ".topmenu.tools.msg"));
                    });
        }
        return menu;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
