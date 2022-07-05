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
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.addon.paramminer.gui.ParamMinerDialog;
import org.zaproxy.addon.paramminer.gui.ParamMinerPanel;
import org.zaproxy.addon.paramminer.gui.PopupMenuParamMiner;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionParamMiner extends ExtensionAdaptor {

    public static final String NAME = "ExtensionParamMiner";
    protected static final String PREFIX = "paramminer";
    private static final String RESOURCES = "resources";
    private static ImageIcon icon;

    private ParamMinerOptions options;
    private ParamMinerPanel paramMinerPanel;
    private ExtensionPopupMenuItem paramMinerDialogPopMenu;
    private ZapMenuItem menu;
    private ParamMinerAPI api;
    private ParamMinerDialog paramMinerDialog;

    private ParamGuesserScanController scanController;

    public ExtensionParamMiner() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void init() {
        super.init();

        options = new ParamMinerOptions();
        scanController = new ParamGuesserScanController();
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

        extensionHook.addOptionsParamSet(options);

        this.api = new ParamMinerAPI();
        extensionHook.addApiImplementor(this.api);

        if (getView() != null) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenu());
            extensionHook.getHookView().addStatusPanel(getParamMinerPanel());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMsg());
        }
    }

    private ExtensionPopupMenuItem getPopupMsg() {
        if (paramMinerDialogPopMenu == null) {
            paramMinerDialogPopMenu =
                    new PopupMenuParamMiner(
                            this, Constant.messages.getString(PREFIX + ".popup.title"));
        }
        return paramMinerDialogPopMenu;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        if (paramMinerPanel != null) {
            paramMinerPanel.unload();
        }
    }

    public void startScan(ParamMinerConfig config) {
        // TODO change the display name based on the config.
        scanController.startScan("Scan", config);
    }

    private ParamMinerPanel getParamMinerPanel() {
        if (paramMinerPanel == null) {
            paramMinerPanel =
                    new ParamMinerPanel(scanController, options, () -> showParamMinerDialog(null));
            scanController.setScansPanel(paramMinerPanel);
        }
        return paramMinerPanel;
    }

    private ZapMenuItem getMenu() {
        if (menu == null) {
            menu = new ZapMenuItem(PREFIX + ".topmenu.tools.title");

            menu.addActionListener(
                    e -> {
                        showParamMinerDialog(null);
                    });
        }
        return menu;
    }

    public void showParamMinerDialog(SiteNode node) {
        if (paramMinerDialog == null) {
            paramMinerDialog =
                    new ParamMinerDialog(
                            this,
                            getView().getMainFrame(),
                            DisplayUtils.getScaledDimension(700, 500));
        }
        paramMinerDialog.init(new Target(node));
        paramMinerDialog.setVisible(true);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
