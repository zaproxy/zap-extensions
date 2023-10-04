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

import java.io.File;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;
import org.apache.commons.io.FileUtils;
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
import org.zaproxy.addon.client.impl.ClientZestRecorder;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProfileManager;
import org.zaproxy.zap.model.ScanEventPublisher;

public class ExtensionClientIntegration extends ExtensionAdaptor {

    public static final String NAME = "ExtensionClientIntegration";

    public static final String ZAP_FIREFOX_PROFILE_NAME = "zap-client-profile";

    protected static final String PREFIX = "client";

    protected static final String RESOURCES = "resources";

    private static final Logger LOGGER = LogManager.getLogger(ExtensionClientIntegration.class);

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionHistory.class, ExtensionNetwork.class, ExtensionSelenium.class);

    private ClientMap clientTree;

    private ClientMapPanel clientMapPanel;
    private ClientDetailsPanel clientDetailsPanel;
    private ClientHistoryPanel clientHistoryPanel;
    private ClientHistoryTableModel clientHistoryTableModel;
    private RedirectScript redirectScript;
    private ClientZestRecorder clientHandler;

    private ClientIntegrationAPI api;

    private EventConsumer eventConsumer;

    private Event lastAjaxSpiderStartEvent;

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
                                false));

        this.api = new ClientIntegrationAPI(this);
        extensionHook.addApiImplementor(this.api);
        extensionHook.addSessionListener(new SessionChangeListener());

        if (hasView()) {
            extensionHook.getHookView().addSelectPanel(getClientMapPanel());
            extensionHook.getHookView().addWorkPanel(getClientDetailsPanel());
            extensionHook.getHookView().addStatusPanel(getClientHistoryPanel());
        }
    }

    @Override
    public void postInit() {
        // The redirectScript is used to pass parameters to the ZAP browser extension
        ExtensionSelenium extSelenium =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);

        redirectScript = new RedirectScript(this.api);
        extSelenium.registerBrowserHook(redirectScript);

        // Check that the custom Firefox profile is available
        ProfileManager pm = extSelenium.getProfileManager(Browser.FIREFOX);
        try {
            Path profileDir = pm.getOrCreateProfile(ZAP_FIREFOX_PROFILE_NAME);
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
        ZAP.getEventBus().unregisterConsumer(eventConsumer);
    }

    @Override
    public boolean canUnload() {
        return true;
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
        } else if (obj instanceof ReportedNode) {
            ReportedNode rn = (ReportedNode) obj;
            String url = rn.getUrl();
            if (url != null && isApiUrl(url)) {
                // Don't record ZAP API calls
                return;
            }
        }
        this.clientHistoryTableModel.addReportedObject(obj);
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
        }

        @Override
        public void sessionAboutToChange(Session session) {
            // Ignore
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
}
