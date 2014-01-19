/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.plugnhack;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

import javax.swing.ImageIcon;

import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.core.proxy.ProxyParam;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.manualrequest.ExtensionManualRequestEditor;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.brk.BreakpointMessageHandler;
import org.zaproxy.zap.extension.brk.ExtensionBreak;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.component.HttpPanelComponentInterface;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelDefaultViewSelector;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.hex.HttpPanelHexView;
import org.zaproxy.zap.extension.plugnhack.brk.ClientBreakpointMessageHandler;
import org.zaproxy.zap.extension.plugnhack.fuzz.ClientMessageFuzzerContentPanel;
import org.zaproxy.zap.extension.plugnhack.fuzz.ClientMessageFuzzerHandler;
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

public class ExtensionPlugNHack extends ExtensionAdaptor implements ProxyListener, SessionChangedListener {

    private static final Logger logger = Logger.getLogger(ExtensionPlugNHack.class);
    
    private static final String REPLACE_ROOT_TOKEN = "__REPLACE_ROOT__";
    private static final String REPLACE_ID_TOKEN = "__REPLACE_ID__";
    private static final String SCRIPT_START =
            "<!-- OWASP ZAP Start of injected code -->\n"
            + "<script>\n";
    
    private static final String SCRIPT_END =
            "\nvar probe = new Probe('" + REPLACE_ROOT_TOKEN + "/OTHER/pnh/other/manifest/','"
            + REPLACE_ID_TOKEN + "');\n"
            + "<!-- OWASP ZAP End of injected code -->\n"
            + "</script>\n";

    public static final String NAME = "ExtensionPlugNHack";
    
    public static final String CLIENT_ACTIVE_ICON_RESOURCE = "/resource/icon/16/029.png";
    public static final String CLIENT_INACTIVE_ICON_RESOURCE = "/resource/icon/16/030.png";

    public static final String FIREFOX_ICON_RESOURCE = "/org/zaproxy/zap/extension/plugnhack/resource/icons/firefox-icon.png";
    public static final String CHROME_ICON_RESOURCE = "/org/zaproxy/zap/extension/plugnhack/resource/icons/chrome-icon.png";
    public static final String IE_ICON_RESOURCE = "/org/zaproxy/zap/extension/plugnhack/resource/icons/ie-icon.png";
    public static final String OPERA_ICON_RESOURCE = "/org/zaproxy/zap/extension/plugnhack/resource/icons/opera-icon.png";
    public static final String SAFARI_ICON_RESOURCE = "/org/zaproxy/zap/extension/plugnhack/resource/icons/safari-icon.png";    

    public static final ImageIcon CHANGED_ICON = new ImageIcon(ExtensionPlugNHack.class.getResource(
            "/org/zaproxy/zap/extension/plugnhack/resource/icons/screwdriver.png"));    
    public static final ImageIcon DROPPED_ICON = new ImageIcon(ExtensionPlugNHack.class.getResource(
            "/org/zaproxy/zap/extension/plugnhack/resource/icons/bin-metal.png"));
    public static final ImageIcon PENDING_ICON = new ImageIcon(ExtensionPlugNHack.class.getResource(
            "/org/zaproxy/zap/extension/plugnhack/resource/icons/hourglass.png"));
    public static final ImageIcon ORACLE_ICON = new ImageIcon(ExtensionPlugNHack.class.getResource(
            "/org/zaproxy/zap/extension/plugnhack/resource/icons/burn.png"));
    
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
    private BreakpointMessageHandler brkMessageHandler = null;
    private ManualClientMessageSendEditorDialog resendDialog = null;
    private ClientMessageFuzzerContentPanel fuzzerContentPanel = null;
    
    private Thread timeoutThread = null;
    private boolean shutdown = false;
    private String pnhScript = null;

    /*
     * TODO
     * Handle mode
     */
    public ExtensionPlugNHack() {
        super();
        initialize();
    }

    private void initialize() {
        this.setName(NAME);
        this.setOrder(101);

        startTimeoutThread();
    }

    private void startTimeoutThread() {
        timeoutThread = new Thread() {
            @Override
            public void run() {
                this.setName("ZAP-pnh-timeout");
                while (!shutdown) {
                    try {
                        sleep(poll);
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
        this.timeoutThread.interrupt();
        super.stop();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        API.getInstance().registerApiImplementor(api);
        extensionHook.addProxyListener(this);

        if (getView() != null) {
            extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuOpenAndMonitorUrl());
            extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuMonitorSubtree());
            extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuMonitorScope());
            extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuResend());
            extensionHook.getHookView().addStatusPanel(getClientsPanel());

            getClientsPanel().setDisplayPanel(getView().getRequestPanel(), getView().getResponsePanel());

            initializeClientsForWorkPanel();

            monitoredClientsPanel = new SessionMonitoredClientsPanel(this.mpm);
            getView().getSessionDialog().addParamPanel(new String[]{}, monitoredClientsPanel, false);

            ExtensionLoader extLoader = Control.getSingleton().getExtensionLoader();

            // setup Breakpoints
            ExtensionBreak extBreak = (ExtensionBreak) extLoader.getExtension(ExtensionBreak.NAME);
            if (extBreak != null) {
                // setup custom breakpoint handler
                brkMessageHandler = new ClientBreakpointMessageHandler(extBreak.getBreakPanel()/*, config*/);
                brkMessageHandler.setEnabledBreakpoints(extBreak.getBreakpointsEnabledList());
                this.mpm.setClientBreakpointMessageHandler(brkMessageHandler);

                // pop up to add the breakpoint
				/*
                 hookMenu.addPopupMenuItem(new PopupMenuAddBreakWebSocket(extBreak));
                 extBreak.addBreakpointsUiManager(getBrkManager());
                 */
            }

            // setup fuzzable extension
            ExtensionFuzz extFuzz = (ExtensionFuzz) extLoader.getExtension(ExtensionFuzz.NAME);
            if (extFuzz != null) {
                //hookMenu.addPopupMenuItem(new ShowFuzzMessageInWebSocketsTabMenuItem(getWebSocketPanel()));

                ClientMessageFuzzerHandler fuzzHandler = new ClientMessageFuzzerHandler(extFuzz, this);
                extFuzz.addFuzzerHandler(ClientMessage.class, fuzzHandler);
                this.fuzzerContentPanel = (ClientMessageFuzzerContentPanel) fuzzHandler.getFuzzerContentPanel();
            }
        }
    }

    @Override
    public boolean canUnload() {
        // TODO need to check everything is stopped / unloaded
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        Control control = Control.getSingleton();
        ExtensionLoader extLoader = control.getExtensionLoader();

        if (View.isInitialised()) {
            // clear up Session Properties
            getView().getSessionDialog().removeParamPanel(monitoredClientsPanel);
        }

        // clear up Breakpoints
		/*
         ExtensionBreak extBreak = (ExtensionBreak) extLoader.getExtension(ExtensionBreak.NAME);
         if (extBreak != null) {
         extBreak.removeBreakpointsUiManager(getBrkManager());
         }
         */

        // clear up fuzzable extension
        ExtensionFuzz extFuzz = (ExtensionFuzz) extLoader.getExtension(ExtensionFuzz.NAME);
        if (extFuzz != null) {
            extFuzz.removeFuzzerHandler(ClientMessage.class);
        }

        // clear up manualrequest extension
        ExtensionManualRequestEditor extManReqEdit = (ExtensionManualRequestEditor) extLoader.getExtension(ExtensionManualRequestEditor.NAME);
        if (extManReqEdit != null) {
            extManReqEdit.removeManualSendEditor(ClientMessage.class);
        }

        if (getView() != null) {
            clearupClientsForWorkPanel();
        }
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
        HttpPanelDefaultViewSelectorFactory viewSelectorFactory = new HexDefaultViewSelectorFactory();
        manager.addRequestDefaultViewSelectorFactory(ClientComponent.NAME, viewSelectorFactory);
        manager.addResponseDefaultViewSelectorFactory(ClientComponent.NAME, viewSelectorFactory);

        // replace the normal Text views with the ones that use syntax highlighting
        viewFactory = new SyntaxHighlightTextViewFactory();
        manager.addRequestViewFactory(ClientComponent.NAME, viewFactory);
        manager.addResponseViewFactory(ClientComponent.NAME, viewFactory);

        // support large payloads on incoming and outgoing messages
		/* TODO
         viewFactory = new ClientLargePayloadViewFactory();
         manager.addRequestViewFactory(ClientComponent.NAME, viewFactory);
         manager.addResponseViewFactory(ClientComponent.NAME, viewFactory);
		
         viewSelectorFactory = new ClientLargePayloadDefaultViewSelectorFactory();
         manager.addRequestDefaultViewSelectorFactory(ClientComponent.NAME, viewSelectorFactory);
         manager.addResponseDefaultViewSelectorFactory(ClientComponent.NAME, viewSelectorFactory);
         */
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
        manager.removeRequestDefaultViewSelectorFactory(ClientComponent.NAME, HexDefaultViewSelectorFactory.NAME);
        manager.removeResponseDefaultViewSelectorFactory(ClientComponent.NAME, HexDefaultViewSelectorFactory.NAME);

        // replace the normal Text views with the ones that use syntax highlighting
        manager.removeRequestViewFactory(ClientComponent.NAME, SyntaxHighlightTextViewFactory.NAME);
        manager.removeResponseViewFactory(ClientComponent.NAME, SyntaxHighlightTextViewFactory.NAME);

        // support large payloads on incoming and outgoing messages
		/* TODO
         manager.removeRequestViewFactory(ClientComponent.NAME, ClientLargePayloadViewFactory.NAME);
         manager.removeResponseViewFactory(ClientComponent.NAME, ClientLargePayloadViewFactory.NAME);
		
         manager.removeRequestDefaultViewSelectorFactory(ClientComponent.NAME, ClientLargePayloadDefaultViewSelectorFactory.NAME);
         manager.removeResponseDefaultViewSelectorFactory(ClientComponent.NAME, ClientLargePayloadDefaultViewSelectorFactory.NAME);
         */
    }

    private ClientsPanel getClientsPanel() {
        if (this.clientsPanel == null) {
            this.clientsPanel = new ClientsPanel(this);
        }
        
        return this.clientsPanel;
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("plugnhack.desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_HOMEPAGE);
        } catch (MalformedURLException e) {
            return null;
        }
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

    protected ManualClientMessageSendEditorDialog getResendDialog() {
        if (resendDialog == null) {
            resendDialog =
                    new ManualClientMessageSendEditorDialog(new ClientMessagePanelSender(this), true, "plugnhack.resend.popup");
        }
        
        return resendDialog;
    }

    @Override
    public int getArrangeableListenerOrder() {
        // TODO Auto-generated method stub
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

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        if (mpm.isMonitored(msg)) {
            try {
                // Inject javascript into response
                String body = msg.getResponseBody().toString();
                int endHeadOffset = body.toLowerCase().indexOf("</head");
                if (endHeadOffset > 0) {
                    logger.debug("Injecting PnH script into " + msg.getRequestHeader().getURI().toString());
                    // this assign the unique id
                    MonitoredPage page = mpm.monitorPage(msg);


                    body = body.substring(0, endHeadOffset) + SCRIPT_START + this.getPnhScript()
                            + SCRIPT_END.replace(REPLACE_ROOT_TOKEN, this.getApiRoot()).replace(REPLACE_ID_TOKEN, page.getId())
                            + body.substring(endHeadOffset);
                    
                    msg.setResponseBody(body);
                    msg.getResponseHeader().setContentLength(body.length());

                } else {
                    logger.debug("Cant inject PnH script into "
                            + msg.getRequestHeader().getURI().toString() + " no head close tag " + msg.getResponseHeader().getStatusCode());
                }
                
            } catch (ApiException e) {
                logger.error(e.getMessage(), e);
            }

        }
        
        return true;
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
        return this.mpm.messageReceived(msg);
    }

    public boolean isBeingMonitored(String clientId) {
        return this.mpm.isBeingMonitored(clientId);
    }

    private String getPnhScript() throws ApiException {
        if (pnhScript == null) {
            pnhScript = ExtensionPlugNHack.getStringReource("resource/pnh_probe.js");
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
     * Called when the specified oracle is invoked in the client, eg as a result on an XSS
     */
    public void oracleInvoked(int id) {
        logger.debug("Oracle invoked for " + id);
        this.oracleManager.oracleInvoked(id);

        if (this.fuzzerContentPanel != null) {
            this.fuzzerContentPanel.flagOracleInvoked(id);
        }
    }

    public String startMonitoring(URI uri) throws HttpMalformedHeaderException {
        return this.mpm.startMonitoring(uri);
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
    public void sessionAboutToChange(Session arg0) {
        // Ignore
    }

    @Override
    public void sessionChanged(Session arg0) {
        this.mpm.reset();
    }

    @Override
    public void sessionModeChanged(Mode arg0) {
        // Ignore
    }

    @Override
    public void sessionScopeChanged(Session arg0) {
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

    private static final class HexDefaultViewSelectorFactory implements HttpPanelDefaultViewSelectorFactory {

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
        if (View.isInitialised()) {
            this.getClientsPanel().messageChanged(msg);
        }
    }

    /* TODO
     private static final class ClientLargePayloadViewFactory implements HttpPanelViewFactory {
		
     public static final String NAME = "ClientLargePayloadViewFactory";

     @Override
     public String getName() {
     return NAME;
     }

     @Override
     public HttpPanelView getNewView() {
     return new ClientLargePayloadView(new ClientLargetPayloadViewModel());
     }

     @Override
     public Object getOptions() {
     return null;
     }
     }
	
     private static final class ClientLargePayloadDefaultViewSelectorFactory implements HttpPanelDefaultViewSelectorFactory {
		
     public static final String NAME = "ClientLargePayloadDefaultViewSelectorFactory";
     private static HttpPanelDefaultViewSelector defaultViewSelector = null;
		
     private HttpPanelDefaultViewSelector getDefaultViewSelector() {
     if (defaultViewSelector == null) {
     createViewSelector();
     }
     return defaultViewSelector;
     }
		
     private synchronized void createViewSelector() {
     if (defaultViewSelector == null) {
     defaultViewSelector = new ClientLargePayloadDefaultViewSelector();
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

     private static final class ClientLargePayloadDefaultViewSelector implements HttpPanelDefaultViewSelector {

     public static final String NAME = "ClientLargePayloadDefaultViewSelector";
		
     @Override
     public String getName() {
     return NAME;
     }
		
     @Override
     public boolean matchToDefaultView(Message aMessage) {
     return ClientLargePayloadUtil.isLargePayload(aMessage);
     }

     @Override
     public String getViewName() {
     return ClientLargePayloadView.NAME;
     }
        
     @Override
     public int getOrder() {
     // has to come before HexDefaultViewSelector
     return 15;
     }
     }
     */
}
