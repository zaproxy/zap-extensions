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

import java.util.List;
import javax.swing.JMenu;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.MainMenuBar;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.ui.ProgressPanel;
import org.zaproxy.addon.commonlib.ui.ZapSortedMenu;
import org.zaproxy.addon.exim.har.HarExporter;
import org.zaproxy.addon.exim.har.HarImporterType;
import org.zaproxy.addon.exim.har.MenuImportHar;
import org.zaproxy.addon.exim.har.PopupMenuItemSaveHarMessage;
import org.zaproxy.addon.exim.log.MenuItemImportLogs;
import org.zaproxy.addon.exim.pcap.MenuItemImportPcap;
import org.zaproxy.addon.exim.sites.MenuPruneSites;
import org.zaproxy.addon.exim.sites.MenuSaveSites;
import org.zaproxy.addon.exim.sites.YamlExporter;
import org.zaproxy.addon.exim.urls.MenuItemImportUrls;
import org.zaproxy.addon.exim.urls.UrlExporter;

public class ExtensionExim extends ExtensionAdaptor {

    public static final String STATS_PREFIX = "stats.exim.";
    public static final String EXIM_OUTPUT_ERROR = "exim.output.error";
    private static final String NAME = "ExtensionExim";
    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionCommonlib.class);

    private Exporter exporter;
    private Importer importer;

    private JMenu menuExport;

    private PopupMenuExportMessages popupMenuExportResponses;
    private PopupMenuExportMessages popupMenuExportMessages;
    private PopupMenuCopyUrls popupMenuCopyUrls;

    public ExtensionExim() {
        super(NAME);
    }

    @Override
    public void init() {
        super.init();
        importer = new Importer();
        this.registerImporterType(new HarImporterType());
    }

    @Override
    public void initModel(Model model) {
        super.initModel(model);

        exporter = new Exporter(model);

        registerExporterType(new HarExporter());
        registerExporterType(new UrlExporter());
        registerExporterType(new YamlExporter());
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (hasView()) {
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuSaveRawMessage());
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuSaveXmlMessage());
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuItemSaveHarMessage());

            if (getExtensionHistory() != null) {
                getMenuExport().add(getPopupMenuExportMessages());
                getMenuExport().add(getPopupMenuExportResponses());
            }

            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuExportContextUrls(
                                    Constant.messages.getString("exim.menu.export.saveurls"),
                                    this));
            getMenuExport()
                    .add(
                            new PopupMenuExportContextUrls(
                                    Constant.messages.getString("exim.menu.export.context.urls"),
                                    this));

            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuExportSelectedUrls(
                                    Constant.messages.getString("exim.menu.export.saveurls"),
                                    this));
            getMenuExport()
                    .add(
                            new PopupMenuExportSelectedUrls(
                                    Constant.messages.getString("exim.menu.export.popup.selected"),
                                    this));

            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuExportUrls(
                                    Constant.messages.getString("exim.menu.export.popup"), this));
            getMenuExport()
                    .add(
                            new PopupMenuExportUrls(
                                    Constant.messages.getString("exim.menu.export.popup"), this));

            extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuCopyUrls());

            MainMenuBar menuBar = getView().getMainFrame().getMainMenuBar();
            menuBar.add(getMenuExport(), menuBar.getMenuCount() - 2); // Before Online and Help

            getMenuExport().add(new MenuSaveSites());
            extensionHook.getHookMenu().addToolsMenuItem(new MenuPruneSites());

            extensionHook.getHookMenu().addImportMenuItem(new MenuImportHar());
            extensionHook.getHookMenu().addImportMenuItem(new MenuItemImportUrls());
            extensionHook.getHookMenu().addImportMenuItem(new MenuItemImportLogs());
            extensionHook.getHookMenu().addImportMenuItem(new MenuItemImportPcap());
        }
        extensionHook.addApiImplementor(new ImportExportApi());
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

    /**
     * Gets the exporter.
     *
     * @return the exporter, never {@code null}.
     * @since 0.13.0
     */
    public Exporter getExporter() {
        return exporter;
    }

    /**
     * Registers an exporter type.
     *
     * @param exporterType the exporter type with id and name.
     * @since 0.18.0
     */
    public void registerExporterType(ExporterType exporterType) {
        Exporter.register(exporterType);
    }

    /**
     * Unregisters the exporter type for the given type ID.
     *
     * @param typeId the export type identifier.
     * @since 0.18.0
     */
    public void unregisterExporterType(String typeId) {
        Exporter.unregister(typeId);
    }

    /**
     * Registers a source exporter for the given source.
     *
     * <p>Only one exporter can be registered per source; a subsequent call replaces the previous
     * registration.
     *
     * @param source the source the exporter handles.
     * @param sourceExporter the exporter.
     * @since 0.19.0
     */
    public void registerSourceExporter(
            ExporterOptions.Source source, SourceExporter sourceExporter) {
        Exporter.registerSourceExporter(source, sourceExporter);
    }

    /**
     * Unregisters the source exporter for the given source.
     *
     * @param source the source whose exporter should be removed.
     * @since 0.19.0
     */
    public void unregisterSourceExporter(ExporterOptions.Source source) {
        Exporter.unregisterSourceExporter(source);
    }

    /**
     * Gets the importer.
     *
     * @return the importer, never {@code null}.
     * @since 0.13.0
     */
    public Importer getImporter() {
        return importer;
    }

    /**
     * Registers an importer type.
     *
     * @param importerType the importer type with id and name.
     * @since 0.18.0
     */
    public void registerImporterType(ImporterType importerType) {
        Importer.register(importerType);
    }

    /**
     * Unregisters the importer type for the given type ID.
     *
     * @param typeId the import type identifier.
     * @since 0.18.0
     */
    public void unregisterImporterType(String typeId) {
        Importer.unregister(typeId);
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
            menuExport = new ZapSortedMenu();
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
