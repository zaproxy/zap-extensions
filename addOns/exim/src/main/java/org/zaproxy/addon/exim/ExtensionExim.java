/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.exim;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.swing.JMenu;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.view.MainMenuBar;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.ui.ProgressPanel;
import org.zaproxy.addon.exim.har.MenuImportHar;
import org.zaproxy.addon.exim.har.PopupMenuItemSaveHarMessage;
import org.zaproxy.addon.exim.log.MenuItemImportLogs;
import org.zaproxy.addon.exim.urls.MenuItemImportUrls;

public class ExtensionExim extends ExtensionAdaptor {

    public static final String STATS_PREFIX = "stats.exim.";
    public static final String EXIM_OUTPUT_ERROR = "exim.output.error";
    private static final String NAME = "ExtensionExim";
    private static final List<Class<? extends Extension>> DEPENDENCIES =
            Collections.unmodifiableList(Arrays.asList(ExtensionCommonlib.class));

    private JMenu menuExport;

    private PopupMenuExportMessages popupMenuExportResponses;
    private PopupMenuExportMessages popupMenuExportMessages;
    private PopupMenuExportContextUrls popupMenuExportContextUrls;
    private PopupMenuExportSelectedUrls popupMenuExportSelectedrls;
    private PopupMenuExportUrls popupMenuExportUrls;
    private PopupMenuCopyUrls popupMenuCopyUrls;

    public ExtensionExim() {
        super(NAME);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuSaveRawMessage());
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuSaveXmlMessage());
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuItemSaveHarMessage());

            // If this is deprecated then the others are as well, due to timing/co-ordination
            if (isDeprecated(org.zaproxy.zap.extension.stdmenus.PopupMenuCopyUrls.class)) {

                if (getExtensionHistory() != null) {
                    getMenuExport().add(getPopupMenuExportMessages());
                    getMenuExport().add(getPopupMenuExportResponses());
                }

                extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuExportContextUrls());
                getMenuExport().add(getPopupMenuExportContextUrls());

                extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuExportSelectedUrls());
                getMenuExport().add(getPopupMenuExportSelectedUrls());

                extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuExportUrls());
                getMenuExport().add(getPopupMenuExportUrls());

                extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuCopyUrls());
            }

            MainMenuBar menuBar = getView().getMainFrame().getMainMenuBar();
            menuBar.add(getMenuExport(), menuBar.getMenuCount() - 2); // Before Online and Help

            extensionHook.getHookMenu().addImportMenuItem(new MenuImportHar());
            extensionHook.getHookMenu().addImportMenuItem(new MenuItemImportUrls());
            extensionHook.getHookMenu().addImportMenuItem(new MenuItemImportLogs());
        }
        extensionHook.addApiImplementor(new ImportExportApi());
    }

    private static boolean isDeprecated(Class<?> classToCheck) {
        return classToCheck.getAnnotation(Deprecated.class) != null;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("exim.description");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("exim.ui.name");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (hasView()) {
            MainMenuBar menuBar = getView().getMainFrame().getMainMenuBar();
            menuBar.remove(getMenuExport());
        }
    }

    public static void updateOutput(String messageKey, String filePath) {
        if (View.isInitialised()) {
            StringBuilder sb = new StringBuilder(128);
            sb.append(Constant.messages.getString(messageKey, filePath)).append('\n');
            View.getSingleton().getOutputPanel().append(sb.toString());
        }
    }

    public static ProgressPanel getProgressPanel() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionCommonlib.class)
                .getProgressPanel();
    }

    private JMenu getMenuExport() {
        if (menuExport == null) {
            menuExport = new JMenu();
            menuExport.setText(Constant.messages.getString("exim.menu.export"));
            menuExport.setMnemonic(Constant.messages.getChar("exim.menu.export.mnemonic"));
        }
        return menuExport;
    }

    private PopupMenuExportMessages getPopupMenuExportMessages() {
        if (popupMenuExportMessages == null) {
            popupMenuExportMessages = new PopupMenuExportMessages(getExtensionHistory(), false);
        }
        return popupMenuExportMessages;
    }

    private PopupMenuExportMessages getPopupMenuExportResponses() {
        if (popupMenuExportResponses == null) {
            popupMenuExportResponses = new PopupMenuExportMessages(getExtensionHistory(), true);
        }
        return popupMenuExportResponses;
    }

    private PopupMenuExportContextUrls getPopupMenuExportContextUrls() {
        if (popupMenuExportContextUrls == null) {
            popupMenuExportContextUrls =
                    new PopupMenuExportContextUrls(
                            Constant.messages.getString("exim.menu.export.context.urls"), this);
        }
        return popupMenuExportContextUrls;
    }

    private PopupMenuExportSelectedUrls getPopupMenuExportSelectedUrls() {
        if (popupMenuExportSelectedrls == null) {
            popupMenuExportSelectedrls =
                    new PopupMenuExportSelectedUrls(
                            Constant.messages.getString("exim.menu.export.popup.selected"), this);
        }
        return popupMenuExportSelectedrls;
    }

    private PopupMenuExportUrls getPopupMenuExportUrls() {
        if (popupMenuExportUrls == null) {
            popupMenuExportUrls =
                    new PopupMenuExportSelectedUrls(
                            Constant.messages.getString("exim.menu.export.popup"), this);
        }
        return popupMenuExportUrls;
    }

    private PopupMenuCopyUrls getPopupMenuCopyUrls() {
        if (popupMenuCopyUrls == null) {
            popupMenuCopyUrls =
                    new PopupMenuCopyUrls(Constant.messages.getString("exim.menu.copyurls.popup"));
        }
        return popupMenuCopyUrls;
    }

    private static ExtensionHistory getExtensionHistory() {
        return Control.getSingleton().getExtensionLoader().getExtension((ExtensionHistory.class));
    }
}
