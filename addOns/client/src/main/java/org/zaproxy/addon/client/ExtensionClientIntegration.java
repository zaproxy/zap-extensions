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

import java.awt.EventQueue;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.SwingUtilities;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriverException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.client.impl.ClientZestRecorder;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientMapWriter;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ClientSideDetails;
import org.zaproxy.addon.client.internal.ReportedElement;
import org.zaproxy.addon.client.internal.ReportedEvent;
import org.zaproxy.addon.client.internal.ReportedObject;
import org.zaproxy.addon.client.pscan.ClientPassiveScanController;
import org.zaproxy.addon.client.pscan.ClientPassiveScanHelper;
import org.zaproxy.addon.client.pscan.ClientPassiveScanRule;
import org.zaproxy.addon.client.pscan.OptionsPassiveScan;
import org.zaproxy.addon.client.spider.AuthenticationHandler;
import org.zaproxy.addon.client.spider.ClientSpider;
import org.zaproxy.addon.client.spider.ClientSpiderApi;
import org.zaproxy.addon.client.spider.ClientSpiderDialog;
import org.zaproxy.addon.client.spider.ClientSpiderPanel;
import org.zaproxy.addon.client.spider.PopupMenuSpider;
import org.zaproxy.addon.client.spider.SpiderScanController;
import org.zaproxy.addon.client.ui.ClientDetailsPanel;
import org.zaproxy.addon.client.ui.ClientHistoryPanel;
import org.zaproxy.addon.client.ui.ClientMapPanel;
import org.zaproxy.addon.client.ui.PopupMenuClientAttack;
import org.zaproxy.addon.client.ui.PopupMenuClientCopyUrls;
import org.zaproxy.addon.client.ui.PopupMenuClientDelete;
import org.zaproxy.addon.client.ui.PopupMenuClientDetailsCopy;
import org.zaproxy.addon.client.ui.PopupMenuClientHistoryCopy;
import org.zaproxy.addon.client.ui.PopupMenuClientOpenInBrowser;
import org.zaproxy.addon.client.ui.PopupMenuClientShowInSites;
import org.zaproxy.addon.client.ui.PopupMenuExportClientMap;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.addon.pscan.PassiveScanRuleProvider;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProfileManager;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.ScanEventPublisher;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.view.ScanStatus;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionClientIntegration extends ExtensionAdaptor {

    public static final String NAME = "ExtensionClientIntegration";

    public static final String ZAP_FIREFOX_PROFILE_NAME = "zap-client-profile";

    private static final String FIREFOX_PROFILES_INI = "profiles.ini";

    public static final String PREFIX = "client";

    protected static final String RESOURCES = "resources";

    private static final Logger LOGGER = LogManager.getLogger(ExtensionClientIntegration.class);

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(
                    ExtensionAlert.class,
                    ExtensionCommonlib.class,
                    ExtensionHistory.class,
                    ExtensionNetwork.class,
                    ExtensionPassiveScan2.class,
                    ExtensionSelenium.class);
    private static final String STATS_EXPORT_CLIENTMAP = PREFIX + ".export.clientmap";

    private ClientMap clientTree;
    private ClientMapPanel clientMapPanel;
    private ClientDetailsPanel clientDetailsPanel;
    private ClientHistoryPanel clientHistoryPanel;
    private ClientSpiderPanel clientSpiderPanel;
    private ClientHistoryTableModel clientHistoryTableModel;
    private RedirectScript redirectScript;
    private ClientZestRecorder clientHandler;
    private SpiderScanController spiderScanController;
    private ClientPassiveScanController passiveScanController;
    private ClientPassiveScanHelper pscanHelper;
    private ClientOptions clientParam;
    private ClientIntegrationAPI api;
    private EventConsumer eventConsumer;
    private Event lastAjaxSpiderStartEvent;
    private static ImageIcon icon;

    private ClientSpiderDialog spiderDialog;
    private ZapMenuItem menuItemCustomScan;

    private ScanStatus pscanStatus;

    private ClientPassiveScanRuleProvider clientPscanRuleProvider =
            new ClientPassiveScanRuleProvider();
    private List<AuthenticationHandler> authHandlers =
            Collections.synchronizedList(new ArrayList<>());

    public ExtensionClientIntegration() {
        super(NAME);
        this.setOrder(410);
    }

    @Override
    public void initModel(Model model) {
        super.initModel(model);
        clientHistoryTableModel = new ClientHistoryTableModel();
        clientTree =
                new ClientMap(
                        new ClientNode(
                                new ClientSideDetails(
                                        Constant.messages.getString("client.tree.title"), null),
                                this.getModel().getSession()));
        spiderScanController =
                new SpiderScanController(
                        this,
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionCommonlib.class)
                                .getValueProvider());
        passiveScanController = new ClientPassiveScanController();
    }

    @Override
    public void initView(ViewDelegate view) {
        pscanStatus =
                new ScanStatus(
                        getIcon("pscan-blue.png"),
                        Constant.messages.getString("client.pscan.footer.label"));
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        this.api = new ClientIntegrationAPI(this);

        extensionHook.addSessionListener(new SessionChangedListenerImpl());
        extensionHook.addOptionsParamSet(getClientParam());
        extensionHook.addApiImplementor(this.api);
        extensionHook.addApiImplementor(new ClientSpiderApi(this));
        extensionHook.addSessionListener(new SessionChangeListener());

        if (hasView()) {
            extensionHook.getHookView().addSelectPanel(getClientMapPanel());
            extensionHook.getHookView().addWorkPanel(getClientDetailsPanel());
            extensionHook.getHookView().addStatusPanel(getClientHistoryPanel());

            extensionHook.getHookMenu().addToolsMenuItem(getMenuItemCustomScan());
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuSpider(
                                    Constant.messages.getString("client.attack.spider"), this));
            extensionHook.getHookView().addStatusPanel(getClientSpiderPanel());

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

            extensionHook
                    .getHookView()
                    .addOptionPanel(new OptionsPassiveScan(passiveScanController));

            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .addFooterToolbarRightComponent(pscanStatus.getCountLabel());

            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new PopupMenuExportClientMap(
                                    Constant.messages.getString("client.tree.popup.export.menu"),
                                    this));
        }
    }

    @Override
    public void optionsLoaded() {
        passiveScanController.setEnabled(getClientParam().isPscanEnabled());
        passiveScanController.setDisabledScanRules(getClientParam().getPscanRulesDisabled());
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
        } catch (WebDriverException e) {
            // Will happen if Firefox is not available.
            LOGGER.debug(e.getMessage(), e);
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        eventConsumer =
                event -> {
                    if (ScanEventPublisher.SCAN_STARTED_EVENT.equals(event.getEventType())) {
                        // Record this for when we get the stopped event
                        lastAjaxSpiderStartEvent = event;
                    } else if (ScanEventPublisher.SCAN_STOPPED_EVENT.equals(event.getEventType())) {
                        // See if we can find any missed URLs in the DOM
                        MissingUrlsThread mut =
                                new MissingUrlsThread(
                                        getModel(), lastAjaxSpiderStartEvent, clientTree.getRoot());
                        lastAjaxSpiderStartEvent = null;
                        mut.start();
                    }
                };

        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionPassiveScan2.class)
                .addPscanRuleProvider(clientPscanRuleProvider);

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
        if (clientTree != null) {
            ZAP.getEventBus().unregisterPublisher(clientTree);
        }
        if (eventConsumer != null) {
            ZAP.getEventBus().unregisterConsumer(eventConsumer);
        }
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionPassiveScan2.class)
                .removePscanRuleProvider(clientPscanRuleProvider);

        if (hasView()) {
            getClientSpiderPanel().unload();
            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .removeFooterToolbarRightComponent(pscanStatus.getCountLabel());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void destroy() {
        this.spiderScanController.stopAllScans();
    }

    public ClientNode getOrAddClientNode(String url, boolean visited, boolean storage) {
        return this.clientTree.getOrAddNode(url, visited, storage);
    }

    public ClientNode getClientNode(String url, boolean visited, boolean storage) {
        return this.clientTree.getNode(url, visited, storage);
    }

    public void clientNodeSelected(ClientNode node) {
        getClientDetailsPanel().setClientNode(node);
    }

    private void clientNodeChanged(ClientNode node) {
        if (!hasView()) {
            return;
        }

        ThreadUtils.invokeAndWaitHandled(() -> clientTree.nodeChanged(node));
    }

    public boolean addComponentToNode(ClientNode node, ClientSideComponent component) {
        if (this.clientTree.addComponentToNode(node, component)) {
            this.clientNodeChanged(node);
            return true;
        }
        return false;
    }

    public boolean setRedirect(String originalUrl, String redirectedUrl) {
        ClientNode node = this.clientTree.setRedirect(originalUrl, redirectedUrl);
        if (node != null) {
            this.clientNodeChanged(node);
            return true;
        }
        return false;
    }

    public boolean setVisited(String url) {
        ClientNode node = this.clientTree.setVisited(url);
        if (node != null) {
            this.clientNodeChanged(node);
            return true;
        }
        return false;
    }

    public boolean setContentLoaded(String url) {
        ClientNode node = clientTree.setContentLoaded(url);
        if (node != null) {
            clientNodeChanged(node);
            return true;
        }
        return false;
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

    private ClientSpiderPanel getClientSpiderPanel() {
        if (clientSpiderPanel == null) {
            clientSpiderPanel =
                    new ClientSpiderPanel(this, this.spiderScanController, this.getClientParam());
        }
        return clientSpiderPanel;
    }

    public void updateAddedCount() {
        if (getView() != null) {
            getClientSpiderPanel().updateAddedCount();
        }
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
        incPscanCount();
        this.passiveScanController
                .getEnabledScanRules()
                .forEach(
                        s -> {
                            try {
                                s.scanReportedObject(obj, pscanHelper);
                            } catch (Exception e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                        });
        decPscanCount();
    }

    private void incPscanCount() {
        if (hasView()) {
            ThreadUtils.invokeLater(pscanStatus::incScanCount);
        }
    }

    private void decPscanCount() {
        if (hasView()) {
            ThreadUtils.invokeLater(
                    () -> {
                        if (pscanStatus.getScanCount() > 0) {
                            pscanStatus.decScanCount();
                        }
                    });
        }
    }

    public ClientPassiveScanController getPassiveScanController() {
        return this.passiveScanController;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    public void addAuthenticationHandler(AuthenticationHandler handler) {
        authHandlers.add(handler);
    }

    public void removeAuthenticationHandler(AuthenticationHandler handler) {
        authHandlers.remove(handler);
    }

    public List<AuthenticationHandler> getAuthenticationHandlers() {
        return Collections.unmodifiableList(authHandlers);
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
            spiderScanController.reset();
            if (hasView()) {
                pscanStatus.setScanCount(0);
            }
        }

        @Override
        public void sessionAboutToChange(Session session) {
            spiderScanController.stopAllScans();
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
        LOGGER.debug("Got zest statement: {}", stmt);
        if (clientHandler == null) {
            LOGGER.debug("Ignoring zest statement as no clientHandler");
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

    @Override
    public List<String> getActiveActions() {
        List<String> activeActions = new ArrayList<>();
        String actionPrefix = Constant.messages.getString("client.activeActionPrefix");
        this.spiderScanController
                .getActiveScans()
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
                                            KeyEvent.VK_C, InputEvent.ALT_DOWN_MASK, false));
            menuItemCustomScan.setEnabled(Control.getSingleton().getMode() != Mode.safe);
            menuItemCustomScan.setIcon(getIcon());

            menuItemCustomScan.addActionListener(e -> showScanDialog((String) null));
        }
        return menuItemCustomScan;
    }

    public static ImageIcon getIcon() {
        if (icon == null) {
            icon = getIcon("spiderClient.png");
        }
        return icon;
    }

    public static ImageIcon getIcon(String name) {
        String resourceName = RESOURCES + "/" + name;
        URL url = ExtensionClientIntegration.class.getResource(resourceName);
        if (url == null) {
            LOGGER.error("No icon with name {}", resourceName);
            return null;
        }
        return DisplayUtils.getScaledIcon(url);
    }

    /**
     * Abbreviates (the middle of) the given display name if greater than 30 characters.
     *
     * @param displayName the display name that might be abbreviated
     * @return the, possibly, abbreviated display name
     */
    private static String abbreviateDisplayName(String displayName) {
        return StringUtils.abbreviateMiddle(displayName, "..", 30);
    }

    public int startScan(
            String url, ClientOptions options, Context context, User user, boolean subtreeOnly)
            throws URIException, NullPointerException {
        return this.startScan(
                abbreviateDisplayName(url),
                null,
                user,
                new Object[] {new URI(url, true), options, context, subtreeOnly});
    }

    public int startScan(
            String displayName, Target target, User user, Object[] contextSpecificObjects) {
        int id =
                this.spiderScanController.startScan(
                        displayName, target, user, contextSpecificObjects);
        if (hasView()) {
            addScanToUi(this.spiderScanController.getScan(id));
        }
        return id;
    }

    public List<ClientSpider> getAllScans() {
        return this.spiderScanController.getAllScans();
    }

    public List<ClientSpider> getActiveScans() {
        return this.spiderScanController.getActiveScans();
    }

    public ClientSpider getScan(int id) {
        return this.spiderScanController.getScan(id);
    }

    public void stopScan(int id) {
        this.spiderScanController.stopScan(id);
    }

    public void stopAllScans() {
        this.spiderScanController.stopAllScans();
    }

    public void pauseScan(int id) {
        this.spiderScanController.pauseScan(id);
    }

    public void pauseAllScans() {
        this.spiderScanController.pauseAllScans();
    }

    public void resumeScan(int id) {
        this.spiderScanController.resumeScan(id);
    }

    public void resumeAllScans() {
        this.spiderScanController.resumeAllScans();
    }

    private void addScanToUi(final ClientSpider scan) {
        if (!EventQueue.isDispatchThread()) {
            SwingUtilities.invokeLater(() -> addScanToUi(scan));
            return;
        }

        this.getClientSpiderPanel().scannerStarted(scan);
        scan.setListener(getClientSpiderPanel());
        this.getClientSpiderPanel().switchView(scan);
        this.getClientSpiderPanel().setTabFocus();
    }

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionAboutToChange(Session session) {
            spiderScanController.reset();

            if (hasView()) {
                getClientSpiderPanel().reset();
                if (spiderDialog != null) {
                    spiderDialog.reset();
                }
            }
        }

        @Override
        public void sessionChanged(final Session session) {
            if (hasView()) {
                ThreadUtils.invokeAndWaitHandled(getClientSpiderPanel()::reset);
            }
        }

        @Override
        public void sessionScopeChanged(Session session) {
            if (hasView()) {
                getClientSpiderPanel().sessionScopeChanged(session);
            }
        }

        @Override
        public void sessionModeChanged(Mode mode) {
            if (Mode.safe.equals(mode)) {
                spiderScanController.stopAllScans();
            }

            if (hasView()) {
                getClientSpiderPanel().sessionModeChanged(mode);
                getMenuItemCustomScan().setEnabled(!Mode.safe.equals(mode));
            }
        }
    }

    protected boolean exportClientMap(String path, boolean isApi) {
        File file = new File(path);
        boolean result = false;
        try (Writer fileWriter = new FileWriter(file, false)) {
            ClientMapWriter.exportClientMap(fileWriter, clientTree);
            result = true;
        } catch (IOException | UncheckedIOException e) {
            LOGGER.warn(
                    "An error occurred while exporting the Client Map: {}",
                    file.getAbsolutePath(),
                    e);
            if (hasView() && !isApi) {
                this.getView()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        "client.tree.export.error", file.getAbsolutePath()));
            }
        }
        Stats.incCounter(STATS_EXPORT_CLIENTMAP);
        return result;
    }

    public boolean exportClientMap(String path) {
        return exportClientMap(path, false);
    }

    /**
     * Registers a client callback implementor. Any requests to the callback URL which have the
     * implementor name as the next element of the path will be passed over to that implementor.
     * Implementors should use their unique ZAP add-on ID to prevent any clashes.
     */
    public void registerClientCallBack(ClientCallBackImplementor callback) {
        this.api.registerClientCallBack(callback);
    }

    /**
     * Unregisters a client callback implementor. Any requests using the implementor name will be
     * ignored.
     */
    public void unregisterClientCallBack(ClientCallBackImplementor callback) {
        this.api.unregisterClientCallBack(callback);
    }

    private class ClientPassiveScanRuleProvider implements PassiveScanRuleProvider {

        @Override
        public void enableAllRules() {
            passiveScanController.enableAllRules();
            getClientParam().setPscanRulesDisabled(List.of());
        }

        private void setRuleStatusFromController() {
            getClientParam()
                    .setPscanRulesDisabled(
                            passiveScanController.getDisabledScanRules().stream()
                                    .map(ClientPassiveScanRule::getId)
                                    .toList());
        }

        @Override
        public void disableAllRules() {
            passiveScanController.disableAllRules();
            setRuleStatusFromController();
        }

        @Override
        public boolean enableRule(int id) {
            if (passiveScanController.enableRule(id)) {
                setRuleStatusFromController();
                return true;
            }
            return false;
        }

        @Override
        public boolean disableRule(int id) {
            if (passiveScanController.disableRule(id)) {
                setRuleStatusFromController();
                return true;
            }
            return false;
        }

        @Override
        public boolean setThreshold(int id, AlertThreshold threshold) {
            if (passiveScanController.setThreshold(id, threshold)) {
                setRuleStatusFromController();
                return true;
            }
            return false;
        }

        @Override
        public List<PassiveScanRule> getRules() {
            return passiveScanController.getRules();
        }

        @Override
        public PassiveScanRule getRule(int id) {
            return passiveScanController.getRule(id);
        }

        @Override
        public boolean hasRule(int id) {
            return passiveScanController.hasRule(id);
        }
    }
}
