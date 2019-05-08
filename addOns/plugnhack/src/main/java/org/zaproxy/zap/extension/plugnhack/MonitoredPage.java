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

import java.util.Date;
import javax.swing.ImageIcon;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

public class MonitoredPage {

    private long index;
    private String id;
    private HttpMessage message;
    private HistoryReference historyReference;
    private int hrefId = -1;
    private SiteNode node = null;
    private Date lastMessage;
    private boolean active = true;
    private ImageIcon icon = null;
    // Configuration info
    private int heartbeat = 0;
    private boolean monitorPostMessage = true;
    private boolean interceptPostMessage = true;
    private boolean monitorEvents = true;
    private boolean interceptEvents = true;
    private boolean hrefPersisted = false;

    public MonitoredPage(String id, HttpMessage message, Date lastMessage) {
        super();
        this.id = id;
        if (message != null && message.getHistoryRef() != null) {
            this.historyReference = message.getHistoryRef();
        } else {
            this.message = message;
        }
        this.lastMessage = lastMessage;
        this.setIcon(message);
    }

    public MonitoredPage(long index, String id, int hrefId) {
        super();
        this.index = index;
        this.id = id;
        this.hrefId = hrefId;
    }

    public MonitoredPage(String id, HistoryReference href, Date lastMessage) {
        super();
        this.id = id;
        // this.message = message;
        this.historyReference = href;
        this.lastMessage = lastMessage;

        try {
            this.setIcon(href.getHttpMessage());
        } catch (Exception e) {
            // Ignore
        }
    }

    private void setIcon(HttpMessage message) {
        String userAgent = message.getRequestHeader().getHeader(HttpHeader.USER_AGENT);
        if (userAgent != null) {
            userAgent = userAgent.toLowerCase();
            if (userAgent.indexOf("firefox") >= 0) {
                this.icon =
                        new ImageIcon(
                                ExtensionPlugNHack.class.getResource(
                                        ExtensionPlugNHack.FIREFOX_ICON_RESOURCE));
            }
            if (userAgent.indexOf("chrome") >= 0) {
                this.icon =
                        new ImageIcon(
                                ExtensionPlugNHack.class.getResource(
                                        ExtensionPlugNHack.CHROME_ICON_RESOURCE));
            }
            if (userAgent.indexOf("msie") >= 0) {
                this.icon =
                        new ImageIcon(
                                ExtensionPlugNHack.class.getResource(
                                        ExtensionPlugNHack.IE_ICON_RESOURCE));
            }
            if (userAgent.indexOf("opera") >= 0) {
                this.icon =
                        new ImageIcon(
                                ExtensionPlugNHack.class.getResource(
                                        ExtensionPlugNHack.OPERA_ICON_RESOURCE));
            }
            if (userAgent.indexOf("safari") >= 0) {
                this.icon =
                        new ImageIcon(
                                ExtensionPlugNHack.class.getResource(
                                        ExtensionPlugNHack.SAFARI_ICON_RESOURCE));
            }
        }
    }

    private void checkMessage() {
        if (this.message != null && this.message.getHistoryRef() != null) {
            /*
             * We dont really want to keep references to HttpMessage as these contain all of the req/resp data
             * and take up a lot of memory.
             * But when we set up new MonitoredPages the HistoryReference is typically not initialized.
             * So we keep the HttpMessage until the HistoryReference is available.
             */
            this.historyReference = message.getHistoryRef();
            this.message = null;
        }
    }

    public String getId() {
        checkMessage();
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public HttpMessage getMessage() {
        checkMessage();
        if (this.historyReference != null) {
            try {
                return this.historyReference.getHttpMessage();
            } catch (Exception e) {
                // Ignore
            }
        }
        return message;
    }

    public HistoryReference getHistoryReference() {
        checkMessage();
        return historyReference;
    }

    public void setHistoryReference(HistoryReference historyReference) {
        this.historyReference = historyReference;
        try {
            if (historyReference != null) {
                this.setIcon(historyReference.getHttpMessage());
            }
        } catch (Exception e) {
            // Ignore
        }
    }

    public int getHrefId() {
        return hrefId;
    }

    public void setMessage(HttpMessage message) {
        this.message = message;
    }

    public Date getLastMessage() {
        checkMessage();
        return lastMessage;
    }

    public void setLastMessage(Date lastMessage) {
        this.lastMessage = lastMessage;
    }

    public SiteNode getNode() {
        checkMessage();
        return node;
    }

    public void setNode(SiteNode node) {
        this.node = node;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public ImageIcon getIcon() {
        checkMessage();
        return this.icon;
    }

    public URI getURI() {
        checkMessage();
        if (this.historyReference != null) {
            try {
                return this.historyReference.getURI();
            } catch (Exception e) {
                // Ignore
            }
            return null;
        } else {
            return this.message.getRequestHeader().getURI();
        }
    }

    public int getHeartbeat() {
        return heartbeat;
    }

    public void setHeartbeat(int heartbeat) {
        this.heartbeat = heartbeat;
    }

    public boolean isMonitorPostMessage() {
        return monitorPostMessage;
    }

    public void setMonitorPostMessage(boolean monitorPostMessage) {
        this.monitorPostMessage = monitorPostMessage;
    }

    public boolean isInterceptPostMessage() {
        return interceptPostMessage;
    }

    public void setInterceptPostMessage(boolean interceptPostMessage) {
        this.interceptPostMessage = interceptPostMessage;
    }

    public boolean isMonitorEvents() {
        return monitorEvents;
    }

    public void setMonitorEvents(boolean monitorEvents) {
        this.monitorEvents = monitorEvents;
    }

    public boolean isInterceptEvents() {
        return interceptEvents;
    }

    public void setInterceptEvents(boolean interceptEvents) {
        this.interceptEvents = interceptEvents;
    }

    public long getIndex() {
        return index;
    }

    public void setIndex(long index) {
        this.index = index;
    }

    public boolean isHrefPersisted() {
        return hrefPersisted;
    }

    public void setHrefPersisted(boolean hrefPersisted) {
        this.hrefPersisted = hrefPersisted;
    }
}
