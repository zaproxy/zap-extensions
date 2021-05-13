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

import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.swing.SwingWorker;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.plugnhack.brk.ClientBreakpointMessageHandler;

public class MonitoredPagesManager {

    public static final String CLIENT_MESSAGE_TYPE_HEARTBEAT = "heartbeat";
    private boolean monitorAllInScope = false;
    private List<Pattern> includeRegexes = new ArrayList<>();
    private List<Pattern> excludeRegexes = new ArrayList<>();
    private List<String> oneTimeURLs = new ArrayList<>();

    private Map<String, MonitoredPage> monitoredPages = new HashMap<>();
    private Map<String, MonitoredPage> inactivePages = new HashMap<>();
    private List<MonitoredPageListener> listeners = new ArrayList<>();
    private List<ClientMessage> queuedMessages = new ArrayList<>();

    private SessionMonitoredClientsPanel sessionPanel =
            null; // Note this wont be initialised in daemon mode

    private int counter = 0;

    private ExtensionPlugNHack extension;
    private ClientBreakpointMessageHandler brkMessageHandler = null;

    private static final Logger logger = LogManager.getLogger(MonitoredPagesManager.class);

    public MonitoredPagesManager(ExtensionPlugNHack ext) {
        this.extension = ext;
    }

    public boolean isMonitored(HttpMessage msg) {
        if (msg == null) {
            return false;
        }
        String uri = msg.getRequestHeader().getURI().toString();
        Mode mode = Control.getSingleton().getMode();
        if (mode.equals(Mode.safe)) {
            return false;
        } else if (mode.equals(Mode.protect)) {
            if (!msg.isInScope()) {
                // In protected mode and not in scope
                logger.debug("URL not in scope in protected mode {}", uri);
                return false;
            }
        }

        if (msg.getRequestHeader().isImage()) {
            logger.debug("URL is an image {}", uri);
            return false;
        }

        // Onetime urls take precedence over everything
        for (String otu : this.oneTimeURLs) {
            if (uri.equals(otu)) {
                logger.debug("URL is a onetime URL {}", uri);
                // Note that this will be removed from the list when we receive the first client
                // message from it
                return true;
            }
        }

        // Then exclude regexes
        for (Pattern pattern : this.excludeRegexes) {
            if (pattern.matcher(uri).matches()) {
                logger.debug("URL excluded {}", uri);
                return false;
            }
        }

        if (this.monitorAllInScope && msg.isInScope()) {
            logger.debug("URL in scope, which is being monitored {}", uri);
            return true;
        }

        for (Pattern pattern : this.includeRegexes) {
            if (pattern.matcher(uri).matches()) {
                logger.debug("URL included {}", uri);
                return true;
            }
        }

        logger.debug("URL not being monitored {}", uri);
        return false;
    }

    private String getUrlRegex(HttpMessage msg) {
        String url = msg.getRequestHeader().getURI().toString();
        if (url.indexOf("?") > 0) {
            url = url.substring(0, url.indexOf("?"));
        }
        url += ".*";
        return url;
    }

    public boolean isExplicitlyIncluded(HttpMessage msg) {
        return this.getIncludeRegexes().contains(this.getUrlRegex(msg));
    }

    public boolean isExplicitlyExcluded(HttpMessage msg) {
        return this.getExcludeRegexes().contains(this.getUrlRegex(msg));
    }

    public void setMonitorSubtree(HttpMessage msg, boolean monitor) {
        String url = this.getUrlRegex(msg);
        Pattern pattern = Pattern.compile(url);

        if (monitor) {
            if (this.isExplicitlyExcluded(msg)) {
                this.removeExcludePattern(pattern);
            } else {
                this.addIncludePattern(pattern);
            }
        } else {
            if (this.isExplicitlyIncluded(msg)) {
                this.removeIncludePattern(pattern);
            } else {
                this.addExcludePattern(pattern);
            }
        }

        if (View.isInitialised()) {
            // Update the sites tree
            setMonitorFlags(msg, monitor);

            if (this.sessionPanel != null) {
                this.sessionPanel.refresh();
                View.getSingleton()
                        .showSessionDialog(
                                Model.getSingleton().getSession(),
                                SessionMonitoredClientsPanel.PANEL_NAME);
            }
        }
    }

    /**
     * Add a 'one time' URL - this URL is 'remembered' until we receive the first client message
     * from it
     *
     * @param uri
     */
    public void setMonitorOnetimeURL(URI uri) {
        this.oneTimeURLs.add(uri.toString());
    }

    private void setMonitorFlags(HttpMessage msg, boolean monitor) {
        // TODO work out which of these actually work
        SiteNode node = null;
        if (msg.getHistoryRef() != null) {
            node = msg.getHistoryRef().getSiteNode();
        }
        if (node == null) {
            node = Model.getSingleton().getSession().getSiteTree().findNode(msg);
        }
        if (node == null) {
            node =
                    Model.getSingleton()
                            .getSession()
                            .getSiteTree()
                            .findNode(msg.getRequestHeader().getURI());
        }
        if (node == null) {
            return;
        }
        this.setMonitorFlags(node, monitor);
    }

    @SuppressWarnings("rawtypes")
    private void setMonitorFlags(SiteNode node, boolean monitor) {

        try {
            HistoryReference href = node.getHistoryReference();
            if (href != null) {
                if (this.isMonitored(href.getHttpMessage())) {
                    node.addCustomIcon(ExtensionPlugNHack.CLIENT_INACTIVE_ICON_RESOURCE, false);
                    // Apply to 'blank' child nodes
                    monitor = true;
                } else {
                    node.removeCustomIcon(ExtensionPlugNHack.CLIENT_INACTIVE_ICON_RESOURCE);
                    // Apply to 'blank' child nodes
                    monitor = false;
                }
            } else if (monitor) {
                // Its a 'blank' node
                node.addCustomIcon(ExtensionPlugNHack.CLIENT_INACTIVE_ICON_RESOURCE, false);
            }
            Enumeration children = node.children();
            while (children.hasMoreElements()) {
                this.setMonitorFlags((SiteNode) children.nextElement(), monitor);
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    protected void setMonitorFlags() {
        // Do in a background thread in case the tree is huge ;)
        SwingWorker<Void, Void> worker =
                new SwingWorker<Void, Void>() {
                    @Override
                    protected Void doInBackground() throws Exception {
                        logger.debug("Refreshing tree with monitor client flags");
                        setMonitorFlags(
                                Model.getSingleton().getSession().getSiteTree().getRoot(), false);
                        return null;
                    }
                };
        worker.execute();
    }

    public void addIncludePattern(Pattern pattern) {
        this.includeRegexes.add(pattern);
    }

    public void removeIncludePattern(Pattern pattern) {
        this.includeRegexes.remove(pattern);
    }

    public void addExcludePattern(Pattern pattern) {
        this.excludeRegexes.add(pattern);
    }

    public void removeExcludePattern(Pattern pattern) {
        this.excludeRegexes.remove(pattern);
    }

    public boolean isMonitorAllInScope() {
        return monitorAllInScope;
    }

    public void setMonitorAllInScope(boolean monitorAllInScope) {
        this.monitorAllInScope = monitorAllInScope;

        if (View.isInitialised()) {
            // Update the sites tree
            setMonitorFlags();

            if (this.sessionPanel != null) {
                this.sessionPanel.refresh();
                View.getSingleton()
                        .showSessionDialog(
                                Model.getSingleton().getSession(),
                                SessionMonitoredClientsPanel.PANEL_NAME);
            }
        }
    }

    protected List<String> getIncludeRegexes() {
        List<String> list = new ArrayList<>(this.includeRegexes.size());
        for (Pattern pattern : this.includeRegexes) {
            list.add(pattern.pattern());
        }
        return list;
    }

    protected List<String> getExcludeRegexes() {
        List<String> list = new ArrayList<>(this.excludeRegexes.size());
        for (Pattern pattern : this.excludeRegexes) {
            list.add(pattern.pattern());
        }
        return list;
    }

    protected void setExcludeRegexes(List<String> lines) {
        this.excludeRegexes.clear();
        for (String line : lines) {
            try {
                this.excludeRegexes.add(Pattern.compile(line));
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
    }

    protected void setIncludeRegexes(List<String> lines) {
        this.includeRegexes.clear();
        for (String line : lines) {
            try {
                this.includeRegexes.add(Pattern.compile(line));
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
    }

    public ApiResponse messageReceived(ClientMessage msg) {
        List<ApiResponse> responseSet = new ArrayList<>();

        MonitoredPage page = this.monitoredPages.get(msg.getClientId());
        if (page != null) {
            page.setLastMessage(new Date());
            // Side effect will (re)set the active icon
            this.getNodeForPage(page);

            String uri = page.getMessage().getRequestHeader().getURI().toString();
            for (String otu : this.oneTimeURLs) {
                if (uri.equals(otu)) {
                    logger.debug("Removing onetime URL {}", uri);
                    this.oneTimeURLs.remove(otu);
                    break;
                }
            }
        }

        if (msg.getType().equals(CLIENT_MESSAGE_TYPE_HEARTBEAT)) {
            // hide heartbeats - could be an option instead?
        } else {
            for (MonitoredPageListener listener : this.listeners) {
                ApiResponse resp = listener.messageReceived(msg);
                if (resp != null) {
                    responseSet.add(resp);
                }
            }
            if (brkMessageHandler != null
                    && !brkMessageHandler.handleMessageReceivedFromClient(msg, false)) {
                // Drop the message
                logger.debug("Dropping message {}", msg.getData());
                msg.setState(ClientMessage.State.dropped);
                // Make sure the message table is updated immediatelly
                this.extension.messageChanged(msg);
            } else {
                responseSet.add(this.msgToResponse(msg, false));
                if (msg.isChanged()) {
                    // Make sure the message table is updated immediatelly
                    this.extension.messageChanged(msg);
                }
            }
        }

        // Add any queued messages
        synchronized (this.queuedMessages) {
            List<ClientMessage> handledMessages = new ArrayList<>();
            for (ClientMessage qmsg : this.queuedMessages) {
                if (qmsg.getClientId().equals(msg.getClientId())) {
                    // Only return messages for this page - simple way to handle multiple browsers
                    // ;)
                    logger.debug(
                            "Adding queued message for {} : {}",
                            qmsg.getClientId(),
                            qmsg.getData());
                    qmsg.setReceived(new Date());
                    responseSet.add(this.msgToResponse(qmsg, true));
                    qmsg.setState(ClientMessage.State.resent);

                    // add to list
                    for (MonitoredPageListener listener : this.listeners) {
                        listener.messageReceived(qmsg);
                    }
                    handledMessages.add(qmsg);
                    extension.persist(qmsg);

                    // TODO Just add one at a time for now - adding multiple messages can cause
                    // problems
                    break;
                }
            }
            for (ClientMessage hmsg : handledMessages) {
                this.queuedMessages.remove(hmsg);
            }
        }

        // return new ApiResponseList("messages", responseSet);
        ApiResponseList resp = new ApiResponseList("messages", responseSet);
        return resp;
    }

    public boolean isBeingMonitored(String clientId) {
        return this.monitoredPages.containsKey(clientId);
    }

    private ApiResponseSet<Object> msgToResponse(ClientMessage msg, boolean resend) {
        Map<String, Object> map = msg.toMap();
        map.put("type", msg.getType());
        if (resend) {
            // This is essentially a new message, so target the endpoint not the original messageid
            map.put("responseTo", msg.getEndpointId());
        } else {
            // This is a 'known' message
            map.put("responseTo", msg.getMessageId());
        }
        return new ApiResponseSet<>("message", map);
    }

    private String getUniqueId() {
        return "ZAP_ID-" + this.counter++;
    }

    public void timeoutPages(int time) {
        long timenow = new Date().getTime();
        long timeout;
        List<MonitoredPage> removeList = new ArrayList<>();
        List<SiteNode> activeNodes = new ArrayList<>();
        for (MonitoredPage page : this.monitoredPages.values()) {
            if (page.getHeartbeat() > 0 && page.getHeartbeat() * 2000 > time) {
                // Extend the timeout if the poll time is set long
                timeout = timenow - (page.getHeartbeat() * 2000);
            } else {
                timeout = timenow - time;
            }
            if (page.getLastMessage().getTime() < timeout) {
                // remove outside the loop
                removeList.add(page);
            } else {
                SiteNode node = this.getNodeForPage(page);
                if (node != null) {
                    activeNodes.add(node);
                }
            }
        }
        for (MonitoredPage page : removeList) {
            this.monitoredPages.remove(page.getId());
            page.setActive(false);
            this.inactivePages.put(page.getId(), page);
            for (MonitoredPageListener listener : this.listeners) {
                listener.stopMonitoringPageEvent(page);
            }
            SiteNode node = this.getNodeForPage(page);
            if (node != null && !activeNodes.contains(node)) {
                // Only remove the active icon if the page isnt open in another tab/browser...
                node.removeCustomIcon(ExtensionPlugNHack.CLIENT_ACTIVE_ICON_RESOURCE);
                HistoryReference href = node.getHistoryReference();
                try {
                    if (href != null && this.isMonitored(href.getHttpMessage())) {
                        node.addCustomIcon(ExtensionPlugNHack.CLIENT_INACTIVE_ICON_RESOURCE, false);
                    }
                } catch (Exception e) {
                    logger.error(e.getMessage(), e);
                }
            }
        }
    }

    private SiteNode getNodeForPage(MonitoredPage page) {
        if (page.getNode() != null) {
            return page.getNode();
        }
        SiteNode node = null;
        if (page.getHistoryReference() != null) {
            node = page.getHistoryReference().getSiteNode();
            if (node == null) {
                node = Model.getSingleton().getSession().getSiteTree().findNode(page.getMessage());
            }
        }
        if (node != null) {
            // Found one, and it probably wont have the active icon
            node.removeCustomIcon(ExtensionPlugNHack.CLIENT_INACTIVE_ICON_RESOURCE);
            node.addCustomIcon(ExtensionPlugNHack.CLIENT_ACTIVE_ICON_RESOURCE, false);
            page.setNode(node);
        }
        return node;
    }

    public MonitoredPage startMonitoring(URI uri) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(uri);
        MonitoredPage page = new MonitoredPage(this.getUniqueId(), msg, new Date());
        this.monitoredPages.put(page.getId(), page);
        for (MonitoredPageListener listener : this.listeners) {
            listener.startMonitoringPageEvent(page);
        }
        return page;
    }

    public void stopMonitoring(String id) {
        MonitoredPage page = this.monitoredPages.remove(id);
        if (page != null) {
            page.setActive(false);
            this.inactivePages.put(id, page);
        }
    }

    public MonitoredPage monitorPage(HttpMessage msg) {
        MonitoredPage page = new MonitoredPage(this.getUniqueId(), msg, new Date());
        this.monitoredPages.put(page.getId(), page);
        for (MonitoredPageListener listener : this.listeners) {
            listener.startMonitoringPageEvent(page);
        }

        this.getNodeForPage(page);

        return page;
    }

    public MonitoredPage getMonitoredPage(String id, boolean incInactive) {
        MonitoredPage page = this.monitoredPages.get(id);
        if (page == null && incInactive) {
            page = this.inactivePages.get(id);
        }
        return page;
    }

    public void reset() {
        this.monitorAllInScope = false;
        this.includeRegexes.clear();
        this.excludeRegexes.clear();
        this.monitoredPages.clear();
        this.inactivePages.clear();
        if (this.sessionPanel != null) {
            this.sessionPanel.refresh();
        }
    }

    public void addListener(MonitoredPageListener listener) {
        this.listeners.add(listener);
    }

    public void removeListener(MonitoredPageListener listener) {
        this.listeners.remove(listener);
    }

    public void setClientBreakpointMessageHandler(
            ClientBreakpointMessageHandler brkMessageHandler) {
        this.brkMessageHandler = brkMessageHandler;
    }

    public boolean isPendingMessages(String clientId) {
        synchronized (this.queuedMessages) {
            for (ClientMessage qmsg : this.queuedMessages) {
                if (clientId.equals(qmsg.getClientId())) {
                    return true;
                }
            }
        }
        return false;
    }

    public void resend(ClientMessage msg) {
        ClientMessage msg2 = new ClientMessage(msg.getClientId(), msg.getJson());
        msg2.setChanged(true);
        this.send(msg2);
    }

    public void send(ClientMessage msg) {
        msg.setState(ClientMessage.State.pending);
        synchronized (this.queuedMessages) {
            logger.debug("Adding message to queue for {} : {}", msg.getClientId(), msg.getData());
            this.queuedMessages.add(msg);
        }
    }

    public void setSessionPanel(SessionMonitoredClientsPanel sessionPanel) {
        this.sessionPanel = sessionPanel;
    }

    public List<String> getActiveClientIds() {
        List<String> list = new ArrayList<>();
        for (MonitoredPage page : this.monitoredPages.values()) {
            list.add(page.getId());
        }
        return list;
    }

    public List<MonitoredPage> getActiveClients() {
        List<MonitoredPage> list = new ArrayList<>();
        for (MonitoredPage page : this.monitoredPages.values()) {
            list.add(page);
        }
        return list;
    }

    public List<String> getInactiveClientIds() {
        List<String> list = new ArrayList<>();
        for (MonitoredPage page : this.inactivePages.values()) {
            list.add(page.getId());
        }
        return list;
    }

    public List<MonitoredPage> getInactiveClients() {
        List<MonitoredPage> list = new ArrayList<>();
        for (MonitoredPage page : this.inactivePages.values()) {
            list.add(page);
        }
        return list;
    }

    public void addInactiveClient(MonitoredPage page) {
        page.setActive(false);
        this.inactivePages.put(page.getId(), page);
    }

    public MonitoredPage getClient(String clientId) {
        MonitoredPage client = this.monitoredPages.get(clientId);
        if (client == null) {
            client = this.inactivePages.get(clientId);
        }
        return client;
    }
}
