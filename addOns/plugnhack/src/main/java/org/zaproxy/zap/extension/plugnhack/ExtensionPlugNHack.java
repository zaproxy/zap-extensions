/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.plugnhack;

import java.awt.Dimension;
import java.awt.EventQueue;
import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.swing.ImageIcon;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.core.proxy.ProxyParam;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DatabaseUnsupportedException;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.brk.ExtensionBreak;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.component.HttpPanelComponentInterface;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelDefaultViewSelector;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.hex.HttpPanelHexView;
import org.zaproxy.zap.extension.plugnhack.brk.ClientBreakpointMessageHandler;
import org.zaproxy.zap.extension.plugnhack.brk.ClientBreakpointsUiManagerInterface;
import org.zaproxy.zap.extension.plugnhack.brk.PopupMenuAddBreakClient;
import org.zaproxy.zap.extension.plugnhack.db.ClientTable;
import org.zaproxy.zap.extension.plugnhack.db.MessageTable;
import org.zaproxy.zap.extension.plugnhack.httppanel.component.ClientComponent;
import org.zaproxy.zap.extension.plugnhack.httppanel.models.ByteClientPanelViewModel;
import org.zaproxy.zap.extension.plugnhack.httppanel.models.StringClientPanelViewModel;
import org.zaproxy.zap.extension.plugnhack.httppanel.views.ClientSyntaxHighlightTextView;
import org.zaproxy.zap.extension.plugnhack.manualsend.ClientMessagePanelSender;
import org.zaproxy.zap.extension.plugnhack.manualsend.ManualClientMessageSendEditorDialog;
import org.zaproxy.zap.view.HttpPanelManager;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelComponentFactory;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelDefaultViewSelectorFactory;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelViewFactory;

public class ExtensionPlugNHack extends ExtensionAdaptor
        implements ProxyListener, SessionChangedListener {

    private static final Logger logger = Logger.getLogger(ExtensionPlugNHack.class);

    private static final String REPLACE_ROOT_TOKEN = "__REPLACE_ROOT__";
    private static final String REPLACE_ID_TOKEN = "__REPLACE_ID__";
    private static final String REPLACE_NONCE = "__REPLACE_NONCE__";
    private static final String SCRIPT_START =
            "<!-- OWASP ZAP Start of injected code -->\n" + "<script>\n";

    private static final String SCRIPT_API = "/OTHER/pnh/other/manifest/";
    private static final String SCRIPT_END =
            "\nvar probe = new Probe('"
                    + REPLACE_ROOT_TOKEN
                    + SCRIPT_API
                    + "?"
                    + API.API_NONCE_PARAM
                    + "="
                    + REPLACE_NONCE
                    + "','"
                    + REPLACE_ID_TOKEN
                    + "');\n"
                    + "<!-- OWASP ZAP End of injected code -->\n"
                    + "</script>\n";

    public static final String NAME = "ExtensionPlugNHack";

    public static final String CLIENT_ACTIVE_ICON_RESOURCE = "/resource/icon/16/029.png";
    public static final String CLIENT_INACTIVE_ICON_RESOURCE = "/resource/icon/16/030.png";

    public static final String FIREFOX_ICON_RESOURCE =
            "/org/zaproxy/zap/extension/plugnhack/resources/icons/firefox-icon.png";
    public static final String CHROME_ICON_RESOURCE =
            "/org/zaproxy/zap/extension/plugnhack/resources/icons/chrome-icon.png";
    public static final String IE_ICON_RESOURCE =
            "/org/zaproxy/zap/extension/plugnhack/resources/icons/ie-icon.png";
    public static final String OPERA_ICON_RESOURCE =
            "/org/zaproxy/zap/extension/plugnhack/resources/icons/opera-icon.png";
    public static final String SAFARI_ICON_RESOURCE =
            "/org/zaproxy/zap/extension/plugnhack/resources/icons/safari-icon.png";

    public static final ImageIcon CLIENT_ACTIVE_ICON =
            new ImageIcon(ZAP.class.getResource(CLIENT_ACTIVE_ICON_RESOURCE));
    public static final ImageIcon CLIENT_INACTIVE_ICON =
            new ImageIcon(ZAP.class.getResource(CLIENT_INACTIVE_ICON_RESOURCE));

    public static final ImageIcon CHANGED_ICON =
            new ImageIcon(
                    ExtensionPlugNHack.class.getResource(
                            "/org/zaproxy/zap/extension/plugnhack/resources/icons/screwdriver.png"));
    public static final ImageIcon DROPPED_ICON =
            new ImageIcon(
                    ExtensionPlugNHack.class.getResource(
                            "/org/zaproxy/zap/extension/plugnhack/resources/icons/bin-metal.png"));
    public static final ImageIcon PENDING_ICON =
            new ImageIcon(
                    ExtensionPlugNHack.class.getResource(
                            "/org/zaproxy/zap/extension/plugnhack/resources/icons/hourglass.png"));
    public static final ImageIcon ORACLE_ICON =
            new ImageIcon(
                    ExtensionPlugNHack.class.getResource(
                            "/org/zaproxy/zap/extension/plugnhack/resources/icons/burn.png"));

    private static final int poll = 3000;

    private ClientsPanel clientsPanel = null;
    private PopupMenuResend popupMenuResend = null;

    private PlugNHackAPI api = new PlugNHackAPI(this);
    private MonitoredPagesManager mpm = new MonitoredPagesManager(this);
    private OracleManager oracleManager = new OracleManager();
    private SessionMonitoredClientsPanel monitoredClientsPanel = null;

    private PopupMenuMonitorSubtree popupMenuMonitorSubtree = null;
    private PopupMenuMonitorScope popupMenuMonitorScope = null;
    private PopupMenuOpenAndMonitorUrl popupMenuOpenAndMonitorUrl = null;
    // TODO Work in progress
    // private PopupMenuShowResponseInBrowser popupMenuShowResponseInBrowser = null;

    private ClientBreakpointMessageHandler brkMessageHandler = null;
    private ManualClientMessageSendEditorDialog resendDialog = null;
    private ClientConfigDialog clientConfigDialog = null;

    private ClientBreakpointsUiManagerInterface brkManager = null;

    private List<String> knownTypes = new ArrayList<String>();

    private Thread timeoutThread = null;
    private boolean shutdown = false;
    private String pnhScript = null;

    private ClientTable clientTable = null;
    private MessageTable messageTable = null;

    /*
     * TODO
     * Handle mode
     */

    public ExtensionPlugNHack() {
        super(NAME);
        this.setOrder(101);
    }

    @Override
    public void databaseOpen(Database db) throws DatabaseUnsupportedException {
        clientTable = new ClientTable();
        db.addDatabaseListener(clientTable);
        try {
            clientTable.databaseOpen(db.getDatabaseServer());
        } catch (DatabaseException e) {
            logger.warn(e.getMessage(), e);
        }

        messageTable = new MessageTable();
        db.addDatabaseListener(messageTable);
        try {
            messageTable.databaseOpen(db.getDatabaseServer());
        } catch (DatabaseException e) {
            logger.warn(e.getMessage(), e);
        }
    }

    private void startTimeoutThread() {
        timeoutThread =
                new Thread() {
                    @Override
                    public void run() {
                        this.setName("ZAP-pnh-timeout");
                        // Cant init extBreak here - Control wont have been initialized
                        boolean ctrlInit = false;
                        ExtensionBreak extBreak = null;
                        while (!shutdown) {
                            try {
                                sleep(poll);

                                if (!ctrlInit && Control.getSingleton() != null) {
                                    extBreak =
                                            (ExtensionBreak)
                                                    Control.getSingleton()
                                                            .getExtensionLoader()
                                                            .getExtension(ExtensionBreak.NAME);
                                    ctrlInit = true;
                                }
                                if (extBreak != null
                                        && (extBreak.getBreakpointManagementInterface()
                                                        .isBreakRequest()
                                                || extBreak.getBreakpointManagementInterface()
                                                        .isBreakResponse())) {
                                    // Dont timeout pages while global breakpoints set
                                    // TODO find a solution for custom break points too
                                    continue;
                                }
                                mpm.timeoutPages(poll * 2);

                            } catch (InterruptedException e) {
                                // ignore
                            }
                        }
                    }
                };

        timeoutThread.start();
    }

    @Override
    public void stop() {
        this.shutdown = true;
        if (timeoutThread != null) {
            this.timeoutThread.interrupt();
        }
        super.stop();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addApiImplementor(api);
        extensionHook.addProxyListener(this);
        extensionHook.addSessionListener(this);

        if (getView() != null) {
            extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuOpenAndMonitorUrl());
            extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuMonitorSubtree());
            extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuMonitorScope());
            extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuResend());
            // TODO Work in progress
            // extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuShowResponseInBrowser());
            extensionHook.getHookView().addStatusPanel(getClientsPanel());

            getClientsPanel()
                    .setDisplayPanel(getView().getRequestPanel(), getView().getResponsePanel());

            initializeClientsForWorkPanel();

            monitoredClientsPanel = new SessionMonitoredClientsPanel(this.mpm);
            getView()
                    .getSessionDialog()
                    .addParamPanel(new String[] {}, monitoredClientsPanel, false);

            ExtensionHelp.enableHelpKey(getClientsPanel(), "addon.plugnhack.pnhclients");

            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuConfigureClient(this));

            ExtensionLoader extLoader = Control.getSingleton().getExtensionLoader();

            // setup Breakpoints
            ExtensionBreak extBreak = (ExtensionBreak) extLoader.getExtension(ExtensionBreak.NAME);
            if (extBreak != null) {
                // setup custom breakpoint handler
                brkMessageHandler =
                        new ClientBreakpointMessageHandler(
                                extBreak.getBreakpointManagementInterface());
                brkMessageHandler.setEnabledBreakpoints(extBreak.getBreakpointsEnabledList());
                this.mpm.setClientBreakpointMessageHandler(brkMessageHandler);

                // pop up to add the breakpoint
                extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuAddBreakClient(extBreak));

                extBreak.addBreakpointsUiManager(getBrkManager());
            }

            startTimeoutThread();
        }
    }

    /* TODO Work in progress
    private PopupMenuShowResponseInBrowser getPopupMenuShowResponseInBrowser() {
    	if (popupMenuShowResponseInBrowser == null) {
    		popupMenuShowResponseInBrowser = new PopupMenuShowResponseInBrowser(this, "Open history in browser TODO");	// TODO
    	}
    	return popupMenuShowResponseInBrowser;
    }
    */

    protected PlugNHackAPI getAPI() {
        return api;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        // Explicitly call "stop()" as it's not being called by the core during/after the unloading.
        // TODO Remove once the bug is fixed in core.
        stop();

        if (View.isInitialised()) {
            // clear up Session Properties
            getView().getSessionDialog().removeParamPanel(monitoredClientsPanel);

            ExtensionLoader extLoader = Control.getSingleton().getExtensionLoader();

            // clear up Breakpoints
            ExtensionBreak extBreak = (ExtensionBreak) extLoader.getExtension(ExtensionBreak.NAME);
            if (extBreak != null) {
                extBreak.removeBreakpointsUiManager(getBrkManager());
            }

            // clear up manualrequest extension
            // ExtensionManualRequestEditor extManReqEdit = (ExtensionManualRequestEditor)
            // extLoader.getExtension(ExtensionManualRequestEditor.NAME);
            // if (extManReqEdit != null) {
            //     extManReqEdit.removeManualSendEditor(ClientMessage.class);
            // }

            clearupClientsForWorkPanel();
        }

        Database db = Model.getSingleton().getDb();
        db.removeDatabaseListener(clientTable);
        db.removeDatabaseListener(messageTable);
    }

    private PopupMenuResend getPopupMenuResend() {
        if (popupMenuResend == null) {
            popupMenuResend = new PopupMenuResend(this);
        }

        return this.popupMenuResend;
    }

    private void initializeClientsForWorkPanel() {
        // Add "HttpPanel" components and views.
        HttpPanelManager manager = HttpPanelManager.getInstance();

        // component factory for outgoing and incoming messages with Text view
        HttpPanelComponentFactory componentFactory = new ClientComponentFactory();
        manager.addRequestComponentFactory(componentFactory);
        manager.addResponseComponentFactory(componentFactory);

        // use same factory for request & response,
        // as Hex payloads are accessed the same way
        HttpPanelViewFactory viewFactory = new ClientHexViewFactory();
        manager.addRequestViewFactory(ClientComponent.NAME, viewFactory);
        manager.addResponseViewFactory(ClientComponent.NAME, viewFactory);

        // add the default Hex view for binary-opcode messages
        HttpPanelDefaultViewSelectorFactory viewSelectorFactory =
                new HexDefaultViewSelectorFactory();
        manager.addRequestDefaultViewSelectorFactory(ClientComponent.NAME, viewSelectorFactory);
        manager.addResponseDefaultViewSelectorFactory(ClientComponent.NAME, viewSelectorFactory);

        // replace the normal Text views with the ones that use syntax highlighting
        viewFactory = new SyntaxHighlightTextViewFactory();
        manager.addRequestViewFactory(ClientComponent.NAME, viewFactory);
        manager.addResponseViewFactory(ClientComponent.NAME, viewFactory);
    }

    private void clearupClientsForWorkPanel() {
        HttpPanelManager manager = HttpPanelManager.getInstance();

        // component factory for outgoing and incoming messages with Text view
        manager.removeRequestComponentFactory(ClientComponentFactory.NAME);
        manager.removeRequestComponents(ClientComponent.NAME);
        manager.removeResponseComponentFactory(ClientComponentFactory.NAME);
        manager.removeResponseComponents(ClientComponent.NAME);

        // use same factory for request & response,
        // as Hex payloads are accessed the same way
        manager.removeRequestViewFactory(ClientComponent.NAME, ClientHexViewFactory.NAME);
        manager.removeResponseViewFactory(ClientComponent.NAME, ClientHexViewFactory.NAME);

        // remove the default Hex view for binary-opcode messages
        manager.removeRequestDefaultViewSelectorFactory(
                ClientComponent.NAME, HexDefaultViewSelectorFactory.NAME);
        manager.removeResponseDefaultViewSelectorFactory(
                ClientComponent.NAME, HexDefaultViewSelectorFactory.NAME);

        // replace the normal Text views with the ones that use syntax highlighting
        manager.removeRequestViewFactory(ClientComponent.NAME, SyntaxHighlightTextViewFactory.NAME);
        manager.removeResponseViewFactory(
                ClientComponent.NAME, SyntaxHighlightTextViewFactory.NAME);
    }

    private ClientsPanel getClientsPanel() {
        if (this.clientsPanel == null) {
            this.clientsPanel = new ClientsPanel(this);
        }

        return this.clientsPanel;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("plugnhack.desc");
    }

    private PopupMenuOpenAndMonitorUrl getPopupMenuOpenAndMonitorUrl() {
        if (popupMenuOpenAndMonitorUrl == null) {
            popupMenuOpenAndMonitorUrl = new PopupMenuOpenAndMonitorUrl(this.mpm);
        }

        return popupMenuOpenAndMonitorUrl;
    }

    private PopupMenuMonitorSubtree getPopupMenuMonitorSubtree() {
        if (popupMenuMonitorSubtree == null) {
            this.popupMenuMonitorSubtree = new PopupMenuMonitorSubtree(this.mpm);
        }

        return this.popupMenuMonitorSubtree;
    }

    private PopupMenuMonitorScope getPopupMenuMonitorScope() {
        if (popupMenuMonitorScope == null) {
            this.popupMenuMonitorScope = new PopupMenuMonitorScope(this.mpm);
        }

        return this.popupMenuMonitorScope;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        if (mpm.isMonitored(msg)) {
            try {
                // Inject javascript into response
                String body = msg.getResponseBody().toString();
                // inject at start
                int startHeadOffset = body.toLowerCase().indexOf("<head");
                boolean injected = false;
                if (startHeadOffset >= 0) {
                    int endHeadTag = body.indexOf('>', startHeadOffset);
                    if (endHeadTag > 0) {
                        endHeadTag++;
                        logger.debug(
                                "Injecting PnH script into "
                                        + msg.getRequestHeader().getURI().toString());
                        // this assign the unique id
                        MonitoredPage page = mpm.monitorPage(msg);
                        try {
                            this.clientTable.insert(page);
                            if (View.isInitialised()) {
                                // Switch to the clients tab, which ensures its visible
                                this.getClientsPanel().setTabFocus();
                            }
                        } catch (SQLException e) {
                            logger.error(e.getMessage(), e);
                        }

                        body =
                                body.substring(0, endHeadTag)
                                        + SCRIPT_START
                                        + this.getPnhScript()
                                        + SCRIPT_END
                                                .replace(REPLACE_ROOT_TOKEN, this.getApiRoot())
                                                .replace(REPLACE_ID_TOKEN, page.getId())
                                                .replace(
                                                        REPLACE_NONCE,
                                                        API.getInstance()
                                                                .getLongLivedNonce(SCRIPT_API))
                                        + body.substring(endHeadTag);
                        msg.setResponseBody(body);
                        msg.getResponseHeader().setContentLength(body.length());
                        injected = true;
                    }
                    if (!injected) {
                        logger.debug(
                                "Cant inject PnH script into "
                                        + msg.getRequestHeader().getURI().toString()
                                        + " no head tag found "
                                        + msg.getResponseHeader().getStatusCode());
                    }
                }
            } catch (ApiException e) {
                logger.error(e.getMessage(), e);
            }
        }
        return true;
    }

    protected ManualClientMessageSendEditorDialog getResendDialog() {
        if (resendDialog == null) {
            resendDialog =
                    new ManualClientMessageSendEditorDialog(
                            new ClientMessagePanelSender(this), true, "plugnhack.resend.popup");
        }

        return resendDialog;
    }
    /*
    public void setMonitored(MonitoredPage page, boolean monitored) {
    	SiteNode node = Model.getSingleton().getSession().getSiteTree().findNode(page.getMessage());
    	if (node != null) {
    		logger.debug("setMonitored " + node.getNodeName() + " " + monitored);
    		if (monitored) {
    			node.addCustomIcon(CLIENT_ACTIVE_ICON_RESOURCE, false);
    		} else {
    			node.removeCustomIcon(CLIENT_ACTIVE_ICON_RESOURCE);
    		}
    	}
    }
    */

    public ApiResponse messageReceived(ClientMessage msg) {
        if (!this.knownTypes.contains(msg.getType())) {
            this.knownTypes.add(msg.getType());
        }
        MonitoredPage page = this.mpm.getClient(msg.getClientId());
        if (page != null && !page.isHrefPersisted()) {
            /*
             * When the pages are initialized the href typically is not available
             */
            if (page.getHistoryReference() != null) {
                try {
                    this.clientTable.update(page);
                } catch (SQLException e) {
                    logger.error(e.getMessage(), e);
                }
            }
        }
        persist(msg);
        return this.mpm.messageReceived(msg);
    }

    protected void persist(ClientMessage cmsg) {
        try {
            if (cmsg.getIndex() >= 0) {
                // Already persisted
                if (cmsg.isChanged()) {
                    // but has been changed, so update
                    this.messageTable.update(cmsg);
                }
            } else if (!cmsg.getType()
                    .equals(MonitoredPagesManager.CLIENT_MESSAGE_TYPE_HEARTBEAT)) {
                // Record everything _except_ heartbeats
                this.messageTable.insert(cmsg);
            }
        } catch (SQLException e) {
            logger.error(e.getMessage(), e);
        }
    }

    public boolean isBeingMonitored(String clientId) {
        return this.mpm.isBeingMonitored(clientId);
    }

    public boolean isSiteBeingMonitored(String site) {
        if (site == null || site.length() == 0) {
            logger.debug("isSiteBeingMonitored " + site + " returning false (empty site)");
            return false;
        }
        for (MonitoredPage page : this.mpm.getActiveClients()) {
            if (page.getURI().toString().startsWith(site)) {
                logger.debug("isSiteBeingMonitored " + site + " returning true");
                return true;
            }
        }
        logger.debug(
                "isSiteBeingMonitored "
                        + site
                        + " returning false (did not match any of the "
                        + this.mpm.getActiveClients().size()
                        + " pages actively monitored)");
        return false;
    }

    @Override
    public int getArrangeableListenerOrder() {
        return 101;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        if (mpm.isMonitored(msg)) {
            // Strip off these headers to force a reload so we can inject the script
            msg.getRequestHeader().setHeader(HttpHeader.IF_MODIFIED_SINCE, null);
            msg.getRequestHeader().setHeader(HttpHeader.IF_NONE_MATCH, null);
        }

        return true;
    }

    private String getPnhScript() throws ApiException {
        if (pnhScript == null) {
            pnhScript = ExtensionPlugNHack.getStringReource("resources/pnh_probe.js");
        }

        return pnhScript;
    }

    public static String getStringReource(String resourceName) throws ApiException {
        InputStream in = null;
        StringBuilder sb = new StringBuilder();
        try {
            in = ExtensionPlugNHack.class.getResourceAsStream(resourceName);
            int numRead = 0;
            byte[] buf = new byte[1024];
            while ((numRead = in.read(buf)) != -1) {
                sb.append(new String(buf, 0, numRead));
            }
            return sb.toString();

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new ApiException(ApiException.Type.INTERNAL_ERROR);

        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
    }

    /*
     * Register an oracle, which is a function injected into the page which can be used to detect things like XSSs
     */
    public int registerOracle(Map<String, String> data) {
        return this.oracleManager.registerOracle(data);
    }

    public void addOracleListnner(OracleListener listenner) {
        this.oracleManager.addListener(listenner);
    }

    public void removeOracleListenner(OracleListener listenner) {
        this.oracleManager.removeListener(listenner);
    }

    /*
     * Called when the specified oracle is invoked in the client, e.g. as a result on an XSS
     */
    public void oracleInvoked(int id) {
        logger.debug("Oracle invoked for " + id);
        this.oracleManager.oracleInvoked(id);
    }

    public String startMonitoring(URI uri) throws HttpMalformedHeaderException {
        MonitoredPage page = this.mpm.startMonitoring(uri);
        try {
            this.clientTable.insert(page);
            if (View.isInitialised()) {
                // Switch to the clients tab, which ensures its visible
                this.getClientsPanel().setTabFocus();
            }
        } catch (SQLException e) {
            logger.error(e.getMessage(), e);
        }
        return page.getId();
    }

    public void stopMonitoring(String id) {
        this.mpm.stopMonitoring(id);
    }

    public void addMonitoredPageListenner(MonitoredPageListener listenner) {
        this.mpm.addListener(listenner);
    }

    public void removeMonitoredPageListenner(MonitoredPageListener listenner) {
        this.mpm.removeListener(listenner);
    }

    protected String getApiRoot() {
        ProxyParam proxyParams = Model.getSingleton().getOptionsParam().getProxyParam();
        return "http://" + proxyParams.getProxyIp() + ":" + proxyParams.getProxyPort();
    }

    @Override
    public void sessionAboutToChange(Session session) {
        // Ignore
    }

    @Override
    public void sessionChanged(final Session session) {
        if (EventQueue.isDispatchThread()) {
            sessionChangedEventHandler(session);

        } else {
            try {
                EventQueue.invokeAndWait(
                        new Runnable() {
                            @Override
                            public void run() {
                                sessionChangedEventHandler(session);
                            }
                        });
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
    }

    private void sessionChangedEventHandler(Session session) {
        this.mpm.reset();

        if (View.isInitialised()) {
            getClientsPanel().reset();
        }

        try {
            ExtensionHistory extHist =
                    (ExtensionHistory)
                            org.parosproxy.paros.control.Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionHistory.NAME);
            if (extHist != null) {
                // Load any clients from the db
                for (MonitoredPage page : this.clientTable.list()) {
                    int hrefId = page.getHrefId();
                    if (hrefId >= 0) {
                        page.setHistoryReference(extHist.getHistoryReference(hrefId));
                    }
                    this.mpm.addInactiveClient(page);
                }

                if (View.isInitialised()) {
                    for (ClientMessage cmsg : this.messageTable.list()) {
                        this.getClientsPanel().messageReceived(cmsg);
                    }
                }
            }
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    @Override
    public void sessionModeChanged(Mode session) {
        // Ignore
    }

    @Override
    public void sessionScopeChanged(Session session) {
        // Ignore
    }

    private static final class ClientComponentFactory implements HttpPanelComponentFactory {

        public static final String NAME = "ClientComponentFactory";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelComponentInterface getNewComponent() {
            return new ClientComponent();
        }

        @Override
        public String getComponentName() {
            return ClientComponent.NAME;
        }
    }

    private static final class ClientHexViewFactory implements HttpPanelViewFactory {

        public static final String NAME = "ClientHexViewFactory";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelView getNewView() {
            return new HttpPanelHexView(new ByteClientPanelViewModel(), false);
        }

        @Override
        public Object getOptions() {
            return null;
        }
    }

    private static final class HexDefaultViewSelector implements HttpPanelDefaultViewSelector {

        public static final String NAME = "HexDefaultViewSelector";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public boolean matchToDefaultView(Message aMessage) {
            // use hex view only when previously selected
            //            if (aMessage instanceof ClientMessageDTO) {
            //                ClientMessageDTO msg = (ClientMessageDTO)aMessage;
            //
            //                return (msg.opcode == ClientMessage.OPCODE_BINARY);
            //            }
            return false;
        }

        @Override
        public String getViewName() {
            return HttpPanelHexView.NAME;
        }

        @Override
        public int getOrder() {
            return 20;
        }
    }

    private static final class HexDefaultViewSelectorFactory
            implements HttpPanelDefaultViewSelectorFactory {

        public static final String NAME = "HexDefaultViewSelectorFactory";
        private static HttpPanelDefaultViewSelector defaultViewSelector = null;

        private HttpPanelDefaultViewSelector getDefaultViewSelector() {
            if (defaultViewSelector == null) {
                createViewSelector();
            }
            return defaultViewSelector;
        }

        private synchronized void createViewSelector() {
            if (defaultViewSelector == null) {
                defaultViewSelector = new HexDefaultViewSelector();
            }
        }

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelDefaultViewSelector getNewDefaultViewSelector() {
            return getDefaultViewSelector();
        }

        @Override
        public Object getOptions() {
            return null;
        }
    }

    private static final class SyntaxHighlightTextViewFactory implements HttpPanelViewFactory {

        public static final String NAME = "SyntaxHighlightTextViewFactory";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelView getNewView() {
            return new ClientSyntaxHighlightTextView(new StringClientPanelViewModel());
        }

        @Override
        public Object getOptions() {
            return null;
        }
    }

    public ClientMessage getSelectedClientMessage() {
        return this.getClientsPanel().getSelectedClientMessage();
    }

    public boolean isPendingMessages(String clientId) {
        return this.mpm.isPendingMessages(clientId);
    }

    public void resend(ClientMessage msg) {
        this.mpm.resend(msg);
    }

    protected void messageChanged(ClientMessage msg) {
        msg.setChanged(true);
        if (View.isInitialised()) {
            this.getClientsPanel().messageChanged(msg);
        }
        this.persist(msg);
    }

    protected ClientBreakpointsUiManagerInterface getBrkManager() {
        if (brkManager == null) {
            ExtensionBreak extBreak =
                    (ExtensionBreak)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionBreak.NAME);
            if (extBreak != null) {
                brkManager = new ClientBreakpointsUiManagerInterface(this, extBreak);
            }
        }
        return brkManager;
    }

    public List<String> getKnownTypes() {
        Collections.sort(this.knownTypes);
        return Collections.unmodifiableList(this.knownTypes);
    }

    public List<String> getActiveClientIds() {
        Collections.sort(this.mpm.getActiveClientIds());
        return Collections.unmodifiableList(this.mpm.getActiveClientIds());
    }

    public List<MonitoredPage> getActiveClients() {
        return this.mpm.getActiveClients();
    }

    public List<String> getInactiveClientIds() {
        Collections.sort(this.mpm.getInactiveClientIds());
        return Collections.unmodifiableList(this.mpm.getInactiveClientIds());
    }

    public List<MonitoredPage> getInactiveClients() {
        return this.mpm.getInactiveClients();
    }

    public void showClientConfigDialog(MonitoredPage page) {
        if (clientConfigDialog == null) {
            clientConfigDialog =
                    new ClientConfigDialog(
                            this, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        }
        clientConfigDialog.init(page);
        clientConfigDialog.setVisible(true);
    }

    public void setClientConfig(MonitoredPage page, String key, Object value) {
        ClientMessage cmsg = new ClientMessage();
        cmsg.setTo("ZAP");
        cmsg.setType("setConfig");
        cmsg.setClientId(page.getId());
        cmsg.set("name", key);
        cmsg.set("value", value);
        this.mpm.send(cmsg);
    }
}
