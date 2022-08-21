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
package org.zaproxy.addon.paramdigger;

import javax.swing.ImageIcon;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.paramdigger.gui.ParamDiggerDialog;
import org.zaproxy.addon.paramdigger.gui.ParamDiggerPanel;
import org.zaproxy.addon.paramdigger.gui.PopupMenuParamDigger;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionParamDigger extends ExtensionAdaptor {

    public static final String NAME = "ExtensionParamDigger";
    protected static final String PREFIX = "paramdigger";
    private static final String RESOURCES = "resources";
    private static ImageIcon icon;

    private ParamDiggerOptions options;
    private ParamDiggerPanel paramDiggerPanel;
    private ExtensionPopupMenuItem paramDiggerDialogPopMenu;
    private ZapMenuItem menu;
    private ParamDiggerAPI api;
    private ParamDiggerDialog paramDiggerDialog;

    private ParamGuesserScanController scanController;

    public ExtensionParamDigger() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void init() {
        super.init();

        options = new ParamDiggerOptions();
        scanController = new ParamGuesserScanController();
    }

    public static ImageIcon getIcon() {
        if (icon == null) {
            icon =
                    new ImageIcon(
                            ExtensionParamDigger.class.getResource(
                                    RESOURCES + "/hard-hat-mine.png"));
        }
        return icon;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(options);

        this.api = new ParamDiggerAPI();
        extensionHook.addApiImplementor(this.api);

        if (getView() != null) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenu());
            extensionHook.getHookView().addStatusPanel(getParamDiggerPanel());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMsg());
        }
    }

    private ExtensionPopupMenuItem getPopupMsg() {
        if (paramDiggerDialogPopMenu == null) {
            paramDiggerDialogPopMenu =
                    new PopupMenuParamDigger(
                            this, Constant.messages.getString(PREFIX + ".popup.title"));
        }
        return paramDiggerDialogPopMenu;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        if (paramDiggerPanel != null) {
            paramDiggerPanel.unload();
        }
    }

    public void startScan(ParamDiggerConfig config) {
        // TODO change the display name based on the config.
        scanController.startScan("Scan", config);
    }

    private ParamDiggerPanel getParamDiggerPanel() {
        if (paramDiggerPanel == null) {
            paramDiggerPanel =
                    new ParamDiggerPanel(
                            scanController, options, () -> showParamDiggerDialog(null));
            scanController.setScansPanel(paramDiggerPanel);
        }
        return paramDiggerPanel;
    }

    private ZapMenuItem getMenu() {
        if (menu == null) {
            menu = new ZapMenuItem(PREFIX + ".topmenu.tools.title");

            menu.addActionListener(
                    e -> {
                        showParamDiggerDialog(null);
                    });
            menu.setIcon(getIcon());
        }
        return menu;
    }

    public void showParamDiggerDialog(HttpMessage node) {
        if (paramDiggerDialog == null) {
            paramDiggerDialog =
                    new ParamDiggerDialog(
                            this,
                            getView().getMainFrame(),
                            DisplayUtils.getScaledDimension(700, 300));
        }
        paramDiggerDialog.init(node);
        paramDiggerDialog.setVisible(true);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
