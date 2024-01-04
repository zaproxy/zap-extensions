/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.client;

import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.ImageIcon;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.client.impl.ClientZestRecorder;
import org.zaproxy.addon.client.pscan.ClientPassiveScanController;
import org.zaproxy.addon.client.pscan.ClientPassiveScanHelper;
import org.zaproxy.addon.client.pscan.OptionsPassiveScan;
import org.zaproxy.addon.client.spider.ClientSpider;
import org.zaproxy.addon.client.spider.ClientSpiderDialog;
import org.zaproxy.addon.client.spider.PopupMenuSpider;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProfileManager;
import org.zaproxy.zap.model.ScanEventPublisher;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionClientIntegration extends ExtensionAdaptor {

    public static final String NAME = "ExtensionClientIntegration";

    public static final String ZAP_FIREFOX_PROFILE_NAME = "zap-client-profile";

    private static final String FIREFOX_PROFILES_INI = "profiles.ini";

    protected static final String PREFIX = "client";

    protected static final String RESOURCES = "resources";

    private static final Logger LOGGER = LogManager.getLogger(ExtensionClientIntegration.class);

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(
                    ExtensionAlert.class,
                    ExtensionHistory.class,
                    ExtensionNetwork.class,
                    ExtensionSelenium.class);

    private ClientMap clientTree;

    private ClientMapPanel clientMapPanel;
    private ClientDetailsPanel clientDetailsPanel;
    private ClientHistoryPanel clientHistoryPanel;
    private ClientHistoryTableModel clientHistoryTableModel;
    private RedirectScript redirectScript;
    private ClientZestRecorder clientHandler;
    private ClientPassiveScanController scanController;
    private ClientPassiveScanHelper pscanHelper;
    private ClientOptions clientParam;
    private ClientIntegrationAPI api;
    private EventConsumer eventConsumer;
    private Event lastAjaxSpiderStartEvent;
    private List<ClientSpider> spiders = Collections.synchronizedList(new ArrayList<>());
    private ImageIcon icon;

    private ClientSpiderDialog spiderDialog;
    private ZapMenuItem menuItemCustomScan;

    public ExtensionClientIntegration() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        clientHistoryTableModel = new ClientHistoryTableModel();
        clientTree =
                new ClientMap(
                        new ClientNode(
                                new ClientSideDetails(
                                        Constant.messages.getString("client.tree.title"), null),
                                this.getModel().getSession()));

        scanController = new ClientPassiveScanController();
        this.api = new ClientIntegrationAPI(this);

        extensionHook.addOptionsParamSet(getClientParam());
        extensionHook.addApiImplementor(this.api);
        extensionHook.addSessionListener(new SessionChangeListener());

        if (hasView()) {
            extensionHook.getHookView().addSelectPanel(getClientMapPanel());
            extensionHook.getHookView().addWorkPanel(getClientDetailsPanel());
            extensionHook.getHookView().addStatusPanel(getClientHistoryPanel());

            if (Constant.isDevBuild()) {
                // Not for release .. yet ;)
                extensionHook.getHookMenu().addToolsMenuItem(getMenuItemCustomScan());
                extensionHook
                        .getHookMenu()
                        .addPopupMenuItem(
                                new PopupMenuSpider(
                                        Constant.messages.getString("client.attack.spider"), this));
            }

            // Client Map menu items
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(new PopupMenuClientAttack(this.getClientMapPanel()));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(new PopupMenuClientCopyUrls(this.getClientMapPanel()));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(new PopupMenuClientDelete(this.getClientMapPanel()));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(new PopupMenuClientOpenInBrowser(this.getClientMapPanel()));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(new PopupMenuClientShowInSites(this.getClientMapPanel()));

            // Client History menu items
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuClientHistoryCopy(
                                    this.getClientHistoryPanel(),
                                    Constant.messages.getString(
                                            "client.history.popup.copy.nodeids"),
                                    ReportedObject::getId));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuClientHistoryCopy(
                                    this.getClientHistoryPanel(),
                                    Constant.messages.getString(
                                            "client.history.popup.copy.nodenames"),
                                    ReportedObject::getNodeName));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuClientHistoryCopy(
                                    this.getClientHistoryPanel(),
                                    Constant.messages.getString("client.history.popup.copy.urls"),
                                    ReportedObject::getUrl));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuClientHistoryCopy(
                                    this.getClientHistoryPanel(),
                                    Constant.messages.getString("client.history.popup.copy.texts"),
                                    ReportedObject::getText));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuClientHistoryCopy(
                                    this.getClientHistoryPanel(),
                                    Constant.messages.getString("client.history.popup.copy.types"),
                                    ReportedObject::getI18nType));

            // Client Details menu items
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuClientDetailsCopy(
                                    this.getClientDetailsPanel(),
                                    Constant.messages.getString("client.details.popup.copy.hrefs"),
                                    ClientSideComponent::getHref));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuClientDetailsCopy(
                                    this.getClientDetailsPanel(),
                                    Constant.messages.getString("client.details.popup.copy.ids"),
                                    ClientSideComponent::getId));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuClientDetailsCopy(
                                    this.getClientDetailsPanel(),
                                    Constant.messages.getString("client.details.popup.copy.texts"),
                                    ClientSideComponent::getText));

            extensionHook.getHookView().addOptionPanel(new OptionsPassiveScan(scanController));
        }
    }

    @Override
    public void optionsLoaded() {
        scanController.setEnabled(getClientParam().isPscanEnabled());
        scanController.setDisabledScanRules(getClientParam().getPscanRulesDisabled());
    }

    @Override
    public void postInit() {
        pscanHelper =
                new ClientPassiveScanHelper(
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionAlert.class),
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionHistory.class));

        // The redirectScript is used to pass parameters to the ZAP browser extension
        ExtensionSelenium extSelenium =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);

        redirectScript = new RedirectScript(this.api);
        extSelenium.registerBrowserHook(redirectScript);

        // Check that the custom Firefox profile is available
        ProfileManager pm = extSelenium.getProfileManager(Browser.FIREFOX);
        try {
            Path profileDir = pm.getOrCreateProfile(ZAP_FIREFOX_PROFILE_NAME);
            if (profileDir != null) {
                File prefFile = profileDir.resolve("extension-preferences.json").toFile();
                if (!prefFile.exists()) {
                    // Create the pref file which enables the extension for all sites
                    InputStream prefIs =
                            getClass()
                                    .getResourceAsStream(
                                            RESOURCES + "/firefox-extension-preferences.json");
                    FileUtils.copyInputStreamToFile(prefIs, prefFile);
                    extSelenium.setDefaultFirefoxProfile(ZAP_FIREFOX_PROFILE_NAME);
                }
                // On macOS we have seen the profile added but not included in profiles.ini
                Path profileIniPath = profileDir.getParent().resolve(FIREFOX_PROFILES_INI);
                if (!profileIniPath.toFile().exists()) {
                    // Ini file is one level higher on macOS than linux
                    profileIniPath =
                            profileIniPath.getParent().getParent().resolve(FIREFOX_PROFILES_INI);
                }
                if (profileIniPath.toFile().exists()) {
                    checkFirefoxProfilesFile(profileIniPath, profileIniPath.relativize(profileDir));
                } else {
                    LOGGER.error(
                            "Failed to find Firefox profiles.ini file, last attempt was {}",
                            profileIniPath);
                }

            } else {
                LOGGER.error(
                        "Failed to get or create Firefox profile {}", ZAP_FIREFOX_PROFILE_NAME);
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        eventConsumer =
                new EventConsumer() {

                    @Override
                    public void eventReceived(Event event) {
                        // Listen for AJAX Spider events
                        if (ScanEventPublisher.SCAN_STARTED_EVENT.equals(event.getEventType())) {
                            // Record this for when we get the stopped event
                            lastAjaxSpiderStartEvent = event;
                        } else if (ScanEventPublisher.SCAN_STOPPED_EVENT.equals(
                                event.getEventType())) {
                            // See if we can find any missed URLs in the DOM
                            MissingUrlsThread mut =
                                    new MissingUrlsThread(
                                            getModel(),
                                            lastAjaxSpiderStartEvent,
                                            clientTree.getRoot());
                            lastAjaxSpiderStartEvent = null;
                            mut.start();
                        }
                    }
                };

        ZAP.getEventBus()
                .registerConsumer(
                        eventConsumer, "org.zaproxy.zap.extension.spiderAjax.SpiderEventPublisher");
    }

    public ClientOptions getClientParam() {
        if (clientParam == null) {
            clientParam = new ClientOptions();
        }
        return clientParam;
    }

    protected void checkFirefoxProfilesFile(Path iniPath, Path profilePath) throws IOException {
        boolean profileFound = false;
        int lastProfile = -1;
        for (String line : Files.readAllLines(iniPath, StandardCharsets.UTF_8)) {
            if (line.startsWith("[Profile")) {
                String numStr = line.substring(8, line.length() - 1);
                try {
                    int thisProfile = Integer.parseInt(numStr);
                    if (thisProfile > lastProfile) {
                        lastProfile = thisProfile;
                    }
                } catch (Exception e) {
                    LOGGER.error(e.getMessage(), e);
                }
            } else if (line.equals("Name=" + ZAP_FIREFOX_PROFILE_NAME)) {
                profileFound = true;
                break;
            }
        }
        if (!profileFound) {
            if (iniPath.toFile().canWrite()) {
                List<String> lines =
                        List.of(
                                "",
                                "[Profile" + (lastProfile + 1) + "]",
                                "Name=" + ZAP_FIREFOX_PROFILE_NAME,
                                "IsRelative=1",
                                "Path=" + profilePath);
                Files.write(iniPath, lines, StandardCharsets.UTF_8, StandardOpenOption.APPEND);
                LOGGER.info("Updated Firefox profiles.ini to add zap-client-profile {}", iniPath);
            } else {
                LOGGER.error(
                        "Cannot write to Firefox profiles.ini file, and it does not contain the zap-client-profile {}",
                        iniPath);
            }
        }
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    @Override
    public void unload() {
        if (redirectScript != null) {
            ExtensionSelenium extSelenium =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionSelenium.class);
            extSelenium.deregisterBrowserHook(redirectScript);
        }
        ZAP.getEventBus().unregisterPublisher(clientTree);
        ZAP.getEventBus().unregisterConsumer(eventConsumer);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void destroy() {
        stopAllSpiders();
    }

    private void stopAllSpiders() {
        spiders.forEach(ClientSpider::stop);
    }

    public ClientNode getOrAddClientNode(String url, boolean visited, boolean storage) {
        return this.clientTree.getOrAddNode(url, visited, storage);
    }

    public void clientNodeSelected(ClientNode node) {
        getClientDetailsPanel().setClientNode(node);
    }

    public void clientNodeChanged(ClientNode node) {
        this.clientTree.nodeChanged(node);
    }

    public void deleteNodes(List<ClientNode> nodes) {
        this.clientTree.deleteNodes(nodes);
        if (View.isInitialised()) {
            String displayedUrl = this.getClientDetailsPanel().getCurrentUrl();
            if (StringUtils.isNotBlank(displayedUrl)
                    && nodes.stream()
                            .anyMatch(n -> displayedUrl.equals(n.getUserObject().getUrl()))) {
                this.getClientDetailsPanel().clear();
            }
        }
    }

    private ClientMapPanel getClientMapPanel() {
        if (clientMapPanel == null) {
            clientMapPanel = new ClientMapPanel(this, clientTree);
        }
        return clientMapPanel;
    }

    private ClientDetailsPanel getClientDetailsPanel() {
        if (clientDetailsPanel == null) {
            clientDetailsPanel = new ClientDetailsPanel();
        }
        return clientDetailsPanel;
    }

    private ClientHistoryPanel getClientHistoryPanel() {
        if (clientHistoryPanel == null) {
            clientHistoryPanel = new ClientHistoryPanel(clientHistoryTableModel);
        }
        return clientHistoryPanel;
    }

    public void addReportedObject(ReportedObject obj) {
        if (obj instanceof ReportedEvent) {
            ReportedEvent ev = (ReportedEvent) obj;
            String url = ev.getUrl();
            if (url != null && isApiUrl(url)) {
                // Don't record ZAP API calls
                return;
            }
        } else if (obj instanceof ReportedElement) {
            ReportedElement rn = (ReportedElement) obj;
            String url = rn.getUrl();
            if (url != null && isApiUrl(url)) {
                // Don't record ZAP API calls
                return;
            }
        }
        this.clientHistoryTableModel.addReportedObject(obj);
        this.scanController
                .getEnabledScanRules()
                .forEach(
                        s -> {
                            try {
                                s.scanReportedObject(obj, pscanHelper);
                            } catch (Exception e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                        });
    }

    public ClientPassiveScanController getPassiveScanController() {
        return this.scanController;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    private class SessionChangeListener implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {
            if (clientMapPanel != null) {
                clientMapPanel.clear();
            }
            if (clientDetailsPanel != null) {
                clientDetailsPanel.clear();
            }
            if (clientHistoryTableModel != null) {
                clientHistoryTableModel.clear();
            }
            spiders.clear();
        }

        @Override
        public void sessionAboutToChange(Session session) {
            stopAllSpiders();
        }

        @Override
        public void sessionScopeChanged(Session session) {
            // Ignore
        }

        @Override
        public void sessionModeChanged(Mode mode) {
            // Ignore
        }
    }

    void addZestStatement(String stmt) throws Exception {
        if (clientHandler == null) {
            return;
        }
        clientHandler.addZestStatement(stmt);
    }

    public void setClientRecorderHelper(ClientZestRecorder clientHandler) {
        this.clientHandler = clientHandler;
    }

    public ClientZestRecorder getClientRecorderHelper() {
        return clientHandler;
    }

    protected static boolean isApiUrl(String url) {
        return url.startsWith(API.API_URL) || url.startsWith(API.API_URL_S);
    }

    /**
     * Run the client spider with the configured options
     *
     * @param url The inital URL to request
     * @return an id which can be used to reference the specific scan.
     */
    public int runSpider(String url) {
        return this.runSpider(url, this.getClientParam());
    }

    /**
     * Run the client spider with the specified options
     *
     * @param url The inital URL to request
     * @param options Custom options.
     * @return an id which can be used to reference the specific scan.
     */
    public int runSpider(String url, ClientOptions options) {
        synchronized (spiders) {
            ClientSpider cs = new ClientSpider(url, options, spiders.size());
            spiders.add(cs);
            cs.start();
            return spiders.indexOf(cs);
        }
    }

    public ClientSpider getSpider(int id) {
        return this.spiders.get(id);
    }

    @Override
    public List<String> getActiveActions() {
        List<String> activeActions = new ArrayList<>();
        String actionPrefix = Constant.messages.getString("client.activeActionPrefix");
        spiders.stream()
                .filter(cs -> cs.isRunning())
                .forEach(
                        cs ->
                                activeActions.add(
                                        MessageFormat.format(actionPrefix, cs.getTargetUrl())));
        return activeActions;
    }

    private void initScanDialog() {
        if (spiderDialog == null) {
            spiderDialog =
                    new ClientSpiderDialog(
                            this,
                            View.getSingleton().getMainFrame(),
                            DisplayUtils.getScaledDimension(700, 300));
        }
        spiderDialog.updateBrowsers();
    }

    public void showScanDialog(SiteNode node) {
        initScanDialog();
        spiderDialog.init(node);
        spiderDialog.setVisible(true);
    }

    public void showScanDialog(String url) {
        initScanDialog();
        spiderDialog.init(url);
        spiderDialog.setVisible(true);
    }

    private ZapMenuItem getMenuItemCustomScan() {
        if (menuItemCustomScan == null) {
            menuItemCustomScan =
                    new ZapMenuItem(
                            "client.spider.menu.tools.label",
                            getView()
                                    .getMenuShortcutKeyStroke(
                                            KeyEvent.VK_C, KeyEvent.ALT_DOWN_MASK, false));
            menuItemCustomScan.setEnabled(Control.getSingleton().getMode() != Mode.safe);
            menuItemCustomScan.setIcon(getIcon());

            menuItemCustomScan.addActionListener(e -> showScanDialog((String) null));
        }
        return menuItemCustomScan;
    }

    public ImageIcon getIcon() {
        if (icon == null) {
            icon =
                    DisplayUtils.getScaledIcon(
                            ExtensionClientIntegration.class.getResource(
                                    ExtensionClientIntegration.RESOURCES + "/spiderClient.png"));
        }
        return icon;
    }
}
