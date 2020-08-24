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
package org.zaproxy.zap.extension.sse;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DatabaseUnsupportedException;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.PersistentConnectionListener;
import org.zaproxy.zap.ZapGetMethod;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.component.HttpPanelComponentInterface;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelDefaultViewSelector;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.hex.HttpPanelHexView;
import org.zaproxy.zap.extension.sse.db.EventStreamStorage;
import org.zaproxy.zap.extension.sse.db.TableEventStream;
import org.zaproxy.zap.extension.sse.ui.EventStreamPanel;
import org.zaproxy.zap.extension.sse.ui.httppanel.component.EventStreamComponent;
import org.zaproxy.zap.extension.sse.ui.httppanel.models.ByteEventStreamPanelViewModel;
import org.zaproxy.zap.extension.sse.ui.httppanel.models.StringEventStreamPanelViewModel;
import org.zaproxy.zap.extension.sse.ui.httppanel.views.EventStreamSyntaxHighlightTextView;
import org.zaproxy.zap.extension.sse.ui.httppanel.views.large.EventStreamLargeEventUtil;
import org.zaproxy.zap.extension.sse.ui.httppanel.views.large.EventStreamLargePayloadView;
import org.zaproxy.zap.extension.sse.ui.httppanel.views.large.EventStreamLargetPayloadViewModel;
import org.zaproxy.zap.view.HttpPanelManager;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelComponentFactory;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelDefaultViewSelectorFactory;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelViewFactory;

/**
 * The Server-Sent Events (SSE) extension was written in December 2012. This specification defines
 * an API for opening an HTTP connection for receiving push notifications from a server in the form
 * of DOM events. See: http://www.w3.org/TR/eventsource/.
 *
 * @author Robert Koch
 */
public class ExtensionServerSentEvents extends ExtensionAdaptor
        implements PersistentConnectionListener, SessionChangedListener {

    private static final Logger logger = Logger.getLogger(ExtensionServerSentEvents.class);
    public static final int HANDSHAKE_LISTENER = 10;

    /** Name of this extension. */
    public static final String NAME = "ExtensionServerSentEvents";

    private Charset charset;

    /** Responsible for storing events. */
    private EventStreamStorage storage;

    /** List of observers added to all event streams. */
    private List<EventStreamObserver> observers = new ArrayList<>();

    private Map<Integer, EventStreamProxy> sseProxies = new HashMap<>();
    private EventStreamPanel panel;

    public ExtensionServerSentEvents() {
        super(NAME);

        charset = Charset.forName("UTF-8");

        setOrder(159);
    }

    @Override
    public void init() {
        super.init();
    }

    private void addObserver(EventStreamObserver observer) {
        synchronized (observers) {
            observers.add(observer);
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addPersistentConnectionListener(this);

        extensionHook.addSessionListener(this);

        if (getView() != null) {

            // setup SSE tab
            EventStreamPanel tab = getEventStreamTab();
            tab.setDisplayPanel(getView().getRequestPanel(), getView().getResponsePanel());
            addObserver(tab);
            extensionHook.addSessionListener(tab.getSessionListener());
            extensionHook.getHookView().addStatusPanel(tab);

            initializeWorkPanel();

            ExtensionHelp.enableHelpKey(tab, "sse.tab");
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        // clear up existing connections
        for (Entry<Integer, EventStreamProxy> sseEntry : sseProxies.entrySet()) {
            EventStreamProxy sseProxy = sseEntry.getValue();
            sseProxy.stop();
        }

        clearUpWorkPanel();
    }

    private EventStreamPanel getEventStreamTab() {
        if (panel == null) {
            panel = new EventStreamPanel(storage.getTable()); // TODO, getBrkManager());
        }
        return panel;
    }

    @Override
    public void databaseOpen(Database db) throws DatabaseException, DatabaseUnsupportedException {
        TableEventStream table = new TableEventStream();
        db.addDatabaseListener(table);
        try {
            table.databaseOpen(db.getDatabaseServer());

            if (panel != null) {
                panel.setTable(table);
            }

            if (storage == null) {
                storage = new EventStreamStorage(table);
                addObserver(storage);
            } else {
                storage.setTable(table);
            }
        } catch (DatabaseException e) {
            logger.warn(e.getMessage(), e);
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("sse.desc");
    }

    /**
     * Add Server-Sent Events stream.
     *
     * @param msg Contains request & response headers.
     * @param remoteReader Content arrives continuously and is forwarded to local client.
     * @param localWriter Received content is written here.
     */
    public void addEventStream(
            HttpMessage msg, final InputStream remoteReader, final OutputStream localWriter) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(remoteReader, charset));
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(localWriter, charset));

        EventStreamProxy proxy = new EventStreamProxy(msg, reader, writer);
        synchronized (observers) {
            for (EventStreamObserver observer : observers) {
                proxy.addObserver(observer);
            }
        }
        proxy.start();
        // TODO: save all proxies
    }

    @Override
    public int getArrangeableListenerOrder() {
        return HANDSHAKE_LISTENER;
    }

    @Override
    public boolean onHandshakeResponse(
            HttpMessage httpMessage, Socket inSocket, ZapGetMethod method) {
        boolean keepSocketOpen = false;

        if (httpMessage.isEventStream()) {
            logger.debug("Got Server-Sent Events stream.");

            ZapGetMethod handshakeMethod = (ZapGetMethod) httpMessage.getUserObject();
            if (handshakeMethod != null) {
                keepSocketOpen = true;

                InputStream inputStream;
                try {
                    inputStream = handshakeMethod.getResponseBodyAsStream();

                    inSocket.setSoTimeout(0);
                    inSocket.setTcpNoDelay(true);
                    inSocket.setKeepAlive(true);

                    addEventStream(httpMessage, inputStream, inSocket.getOutputStream());
                } catch (IOException e) {
                    logger.warn(e.getMessage(), e);
                    keepSocketOpen = false;
                }
            } else {
                logger.error("Was not able to retrieve input stream.");
            }
        }

        return keepSocketOpen;
    }

    @Override
    public void sessionChanged(final Session session) {}

    @Override
    public void sessionAboutToChange(Session session) {
        if (View.isInitialised()) {
            // Prevent the table from being used
            //			getWebSocketPanel().setTable(null);
            storage.setTable(null);
        }

        // close existing connections
        synchronized (sseProxies) {
            for (EventStreamProxy sseProxy : sseProxies.values()) {
                sseProxy.stop();
            }
            sseProxies.clear();
        }
    }

    @Override
    public void sessionScopeChanged(Session session) {}

    @Override
    public void sessionModeChanged(Mode mode) {}

    public static int compareTo(EventStreamObserver base, EventStreamObserver other) {
        int myOrder = base.getServerSentEventObservingOrder();
        int otherOrder = other.getServerSentEventObservingOrder();

        if (myOrder < otherOrder) {
            return -1;
        } else if (myOrder > otherOrder) {
            return 1;
        }

        return 0;
    }

    private void initializeWorkPanel() {
        // Add "HttpPanel" components and views.
        HttpPanelManager manager = HttpPanelManager.getInstance();

        // component factory for outgoing and incoming messages with Text view
        HttpPanelComponentFactory componentFactory = new EventStreamComponentFactory();
        manager.addResponseComponentFactory(componentFactory);

        // use same factory for request & response,
        // as Hex payloads are accessed the same way
        HttpPanelViewFactory viewFactory = new EventStreamHexViewFactory();
        manager.addResponseViewFactory(EventStreamComponent.NAME, viewFactory);

        // add the default Hex view for binary-opcode messages
        HttpPanelDefaultViewSelectorFactory viewSelectorFactory =
                new HexDefaultViewSelectorFactory();
        manager.addResponseDefaultViewSelectorFactory(
                EventStreamComponent.NAME, viewSelectorFactory);

        // replace the normal Text views with the ones that use syntax highlighting
        viewFactory = new SyntaxHighlightTextViewFactory();
        manager.addResponseViewFactory(EventStreamComponent.NAME, viewFactory);

        // support large payloads on incoming and outgoing messages
        viewFactory = new EventStreamLargePayloadViewFactory();
        manager.addResponseViewFactory(EventStreamComponent.NAME, viewFactory);

        viewSelectorFactory = new EventStreamLargeEventDefaultViewSelectorFactory();
        manager.addResponseDefaultViewSelectorFactory(
                EventStreamComponent.NAME, viewSelectorFactory);
    }

    private void clearUpWorkPanel() {
        HttpPanelManager manager = HttpPanelManager.getInstance();

        // component factory for outgoing and incoming messages with Text view
        manager.removeRequestComponentFactory(EventStreamComponentFactory.NAME);
        manager.removeRequestComponents(EventStreamComponent.NAME);
        manager.removeResponseComponentFactory(EventStreamComponentFactory.NAME);
        manager.removeResponseComponents(EventStreamComponent.NAME);

        // use same factory for request & response,
        // as Hex payloads are accessed the same way
        manager.removeResponseViewFactory(
                EventStreamComponent.NAME, EventStreamHexViewFactory.NAME);

        // remove the default Hex view for binary-opcode messages
        manager.removeResponseDefaultViewSelectorFactory(
                EventStreamComponent.NAME, HexDefaultViewSelectorFactory.NAME);

        // replace the normal Text views with the ones that use syntax highlighting
        manager.removeResponseViewFactory(
                EventStreamComponent.NAME, SyntaxHighlightTextViewFactory.NAME);

        // support large payloads on incoming and outgoing messages
        manager.removeResponseViewFactory(
                EventStreamComponent.NAME, EventStreamLargeEventDefaultViewSelectorFactory.NAME);
        manager.removeResponseDefaultViewSelectorFactory(
                EventStreamComponent.NAME, EventStreamLargeEventDefaultViewSelectorFactory.NAME);
    }

    /**
     * The component returned by this factory contain the normal text view (without syntax
     * highlighting).
     */
    private static final class EventStreamComponentFactory implements HttpPanelComponentFactory {

        public static final String NAME = "EventStreamComponentFactory";

        @Override
        public HttpPanelComponentInterface getNewComponent() {
            return new EventStreamComponent();
        }

        @Override
        public String getComponentName() {
            return EventStreamComponent.NAME;
        }

        @Override
        public String getName() {
            return NAME;
        }
    }

    private static final class EventStreamHexViewFactory implements HttpPanelViewFactory {

        public static final String NAME = "EventStreamHexViewFactory";

        @Override
        public HttpPanelView getNewView() {
            return new HttpPanelHexView(new ByteEventStreamPanelViewModel(), false);
        }

        @Override
        public Object getOptions() {
            return null;
        }

        @Override
        public String getName() {
            return NAME;
        }
    }

    private static final class HexDefaultViewSelector implements HttpPanelDefaultViewSelector {

        @Override
        public String getName() {
            return "HexDefaultViewSelector";
        }

        @Override
        public boolean matchToDefaultView(Message aMessage) {
            // use hex view only when previously selected
            //            if (aMessage instanceof WebSocketMessageDTO) {
            //                WebSocketMessageDTO msg = (WebSocketMessageDTO)aMessage;
            //
            //                return (msg.opcode == WebSocketMessage.OPCODE_BINARY);
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
        public HttpPanelDefaultViewSelector getNewDefaultViewSelector() {
            return getDefaultViewSelector();
        }

        @Override
        public Object getOptions() {
            return null;
        }

        @Override
        public String getName() {
            return NAME;
        }
    }

    private static final class SyntaxHighlightTextViewFactory implements HttpPanelViewFactory {

        public static final String NAME = "SyntaxHighlightTextViewFactory";

        @Override
        public HttpPanelView getNewView() {
            return new EventStreamSyntaxHighlightTextView(new StringEventStreamPanelViewModel());
        }

        @Override
        public Object getOptions() {
            return null;
        }

        @Override
        public String getName() {
            return NAME;
        }
    }

    private static final class EventStreamLargePayloadViewFactory implements HttpPanelViewFactory {

        public static final String NAME = "EventStreamLargePayloadViewFactory";

        @Override
        public HttpPanelView getNewView() {
            return new EventStreamLargePayloadView(new EventStreamLargetPayloadViewModel());
        }

        @Override
        public Object getOptions() {
            return null;
        }

        @Override
        public String getName() {
            return NAME;
        }
    }

    private static final class EventStreamLargeEventDefaultViewSelectorFactory
            implements HttpPanelDefaultViewSelectorFactory {

        public static final String NAME = "EventStreamLargeEventDefaultViewSelectorFactory";

        private static HttpPanelDefaultViewSelector defaultViewSelector = null;

        private HttpPanelDefaultViewSelector getDefaultViewSelector() {
            if (defaultViewSelector == null) {
                createViewSelector();
            }
            return defaultViewSelector;
        }

        private synchronized void createViewSelector() {
            if (defaultViewSelector == null) {
                defaultViewSelector = new EventStreamLargePayloadDefaultViewSelector();
            }
        }

        @Override
        public HttpPanelDefaultViewSelector getNewDefaultViewSelector() {
            return getDefaultViewSelector();
        }

        @Override
        public Object getOptions() {
            return null;
        }

        @Override
        public String getName() {
            return NAME;
        }
    }

    private static final class EventStreamLargePayloadDefaultViewSelector
            implements HttpPanelDefaultViewSelector {

        @Override
        public String getName() {
            return "EventStreamLargePayloadDefaultViewSelector";
        }

        @Override
        public boolean matchToDefaultView(Message aMessage) {
            return EventStreamLargeEventUtil.isLargeEvent(aMessage);
        }

        @Override
        public String getViewName() {
            return EventStreamLargePayloadView.NAME;
        }

        @Override
        public int getOrder() {
            // has to come before HexDefaultViewSelector
            return 15;
        }
    }
}
