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

import java.awt.CardLayout;
import java.awt.Font;
import javax.swing.ImageIcon;
import javax.swing.JTextPane;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionParamMiner extends ExtensionAdaptor {

    public static final String NAME = "ExtensionParamMiner";
    protected static final String PREFIX = "paramminer";
    private static final String RESOURCES = "resources";

    private ImageIcon getIcon() {
        return new ImageIcon(ExtensionParamMiner.class.getResource(RESOURCES + "/pickaxe.png"));
    }

    private ZapMenuItem menu;
    private AbstractPanel statusPanel;

    private ParamMinerAPI api;

    private static final Logger LOGGER = LogManager.getLogger(ExtensionParamMiner.class);

    public ExtensionParamMiner() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        this.api = new ParamMinerAPI();
        extensionHook.addApiImplementor(this.api);

        if (getView() != null) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenu());
            extensionHook.getHookView().addStatusPanel(getStatusPanel());
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

    private AbstractPanel getStatusPanel() {
        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new CardLayout());
            statusPanel.setName(Constant.messages.getString(PREFIX + ".panel.title"));
            statusPanel.setIcon(getIcon());
            JTextPane pane = new JTextPane();
            pane.setEditable(false);
            pane.setFont(FontUtils.getFont("Dialog", Font.PLAIN));
            pane.setContentType("text/html");
            pane.setText(Constant.messages.getString(PREFIX + ".panel.msg"));
            statusPanel.add(pane);
        }
        return statusPanel;
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
