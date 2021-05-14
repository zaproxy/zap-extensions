/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket;

import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;

/**
 * Data Transfer Object used for displaying WebSocket connection channels. Intended to decouple user
 * interface representation from version specific {@link WebSocketProxy}.
 */
public class WebSocketChannelDTO implements Comparable<WebSocketChannelDTO> {

    /** ChannelId. */
    private Integer id;

    /** Is not necessarily the same as the {@link WebSocketChannelDTO#url}. */
    private String host;

    /** Port where this channel is connected at. Usually 80 or 443. */
    private Integer port;

    /** URL used in HTTP handshake. */
    private String url;

    /** Timestamp taken, when connection was established successfully. */
    private Long startTimestamp;

    /** Timestamp of close, otherwise <code>null</code>. */
    private Long endTimestamp;

    /** Id of handshake message. */
    private Integer historyId;

    public WebSocketChannelDTO() {}

    public WebSocketChannelDTO(String host) {
        this.host = host;
    }

    /**
     * Determined upon {@link #startTimestamp} and {@link #endTimestamp}.
     *
     * @return True if connection is still alive.
     */
    public boolean isConnected() {
        if (startTimestamp != null && endTimestamp == null) {
            return true;
        }
        return false;
    }

    /** @return Null or HTTP message containing handshake. */
    public HistoryReference getHandshakeReference() {
        if (historyId == null) {
            return null;
        }

        try {
            return new HistoryReference(historyId);
        } catch (HttpMalformedHeaderException e) {
            return null;
        } catch (DatabaseException e) {
            return null;
        }
    }

    public boolean isInScope() {
        return Model.getSingleton().getSession().isInScope(getContextUrl());
    }

    /**
     * Returns URL without trailing slash and without parameters. This representation is used for
     * the Mode+Context feature.
     *
     * @return
     */
    public String getContextUrl() {
        if (url == null) {
            return null;
        }

        if (url.indexOf("?") != -1) {
            url = url.substring(0, url.indexOf("?"));
        }

        return url.replaceFirst("/$", "");
    }

    @Override
    public String toString() {
        if (port != null && id != null) {
            return host + ":" + port + " (#" + id + ")";
        }
        return host;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null) {
            return false;
        }
        if (getClass() != object.getClass()) {
            return false;
        }
        WebSocketChannelDTO other = (WebSocketChannelDTO) object;
        if (id == null) {
            if (other.id != null) {
                return false;
            }
        } else if (!id.equals(other.id)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        return 31 + ((id == null) ? 0 : id.hashCode());
    }

    /**
     * Used for sorting items. If two items have identical host names and ports, the channel number
     * is used to determine order.
     */
    @Override
    public int compareTo(WebSocketChannelDTO other) {
        int result = host.compareTo(other.host);

        if (result == 0) {
            result = port.compareTo(other.port);
            if (result == 0) {
                return id.compareTo(other.id);
            }
        }

        return result;
    }

    public String getFullUri() {
        StringBuilder regex = new StringBuilder();
        if (url.matches(".*[^:/]/.*")) {
            // place port into regex
            String wsUri = url.replaceFirst("([^:/])/", "$1:" + port + "/");

            // transform http/https to ws/wss
            wsUri = wsUri.replaceFirst("http(s?://)", "ws$1");
            regex.append(wsUri);
        } else {
            if (port == 80) {
                regex.append("ws://");
            } else {
                regex.append("wss://");
            }
            regex.append(host);
            regex.append(":");
            regex.append(port);
        }
        return regex.toString();
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public Long getStartTimestamp() {
        return startTimestamp;
    }

    public void setStartTimestamp(Long startTimestamp) {
        this.startTimestamp = startTimestamp;
    }

    public Long getEndTimestamp() {
        return endTimestamp;
    }

    public void setEndTimestamp(Long endTimestamp) {
        this.endTimestamp = endTimestamp;
    }

    public Integer getHistoryId() {
        return historyId;
    }

    public void setHistoryId(Integer historyId) {
        this.historyId = historyId;
    }
}
