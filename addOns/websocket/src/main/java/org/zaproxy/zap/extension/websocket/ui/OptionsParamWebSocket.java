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
package org.zaproxy.zap.extension.websocket.ui;

import org.apache.commons.configuration.FileConfiguration;
import org.parosproxy.paros.common.AbstractParam;

public class OptionsParamWebSocket extends AbstractParam {
    //    private static Logger logger = LogManager.getLogger(OptionsParamWebSocket.class);

    public static final String FORWARD_ALL = "websocket.forwardAll";
    public static final String BREAK_ON_PING_PONG = "websocket.breakOnPingPong";
    public static final String BREAK_ON_ALL = "websocket.breakOnAll";
    private static final String CONFIRM_REMOVE_PROXY_EXCLUDE_REGEX_KEY =
            "websocket.confirmRemoveProxyExcludeRegex";
    private static final String REMOVE_EXTENSIONS_HEADER_KEY = "websocket.removeExtensionsHeader";

    private boolean isForwardAll;
    private boolean isBreakOnPingPong;
    private boolean isBreakOnAll;
    private boolean confirmRemoveProxyExcludeRegex;

    /**
     * Flag that controls whether or not the header {@code Sec-WebSocket-Extensions} should be
     * removed from the handshake messages.
     *
     * <p>Default is {@code true}.
     *
     * @see #REMOVE_EXTENSIONS_HEADER_KEY
     * @see #setRemoveExtensionsHeader(boolean)
     */
    private boolean removeExtensionsHeader = true;

    @Override
    protected void parse() {
        FileConfiguration cfg = getConfig();
        isForwardAll = cfg.getBoolean(FORWARD_ALL, false);
        isBreakOnPingPong = cfg.getBoolean(BREAK_ON_PING_PONG, false);
        isBreakOnAll = cfg.getBoolean(BREAK_ON_ALL, false);
        confirmRemoveProxyExcludeRegex =
                cfg.getBoolean(CONFIRM_REMOVE_PROXY_EXCLUDE_REGEX_KEY, false);
        removeExtensionsHeader = cfg.getBoolean(REMOVE_EXTENSIONS_HEADER_KEY, true);
    }

    /**
     * If true, then all WebSocket communication is forwarded, but not stored in database, nor shown
     * in user interface.
     *
     * @return True if all traffic should only be forwarded.
     */
    public boolean isForwardAll() {
        return isForwardAll;
    }

    /**
     * @see OptionsParamWebSocket#isForwardAll()
     * @param isForwardAll
     */
    public void setForwardAll(boolean isForwardAll) {
        this.isForwardAll = isForwardAll;
        getConfig().setProperty(FORWARD_ALL, isForwardAll);
    }

    /**
     * If false, then no PING/PONG messages are caught when:
     *
     * <ul>
     *   <li>enabled <i>break on all requests/responses</i> buttons are enabled
     *   <li>stepping through to next request/response
     * </ul>
     *
     * @return True if it should break also on ping & pong messages.
     */
    public boolean isBreakOnPingPong() {
        return isBreakOnPingPong;
    }

    /**
     * @see OptionsParamWebSocket#isBreakOnPingPong()
     * @param isCatchPingPong
     */
    public void setBreakOnPingPong(boolean isCatchPingPong) {
        this.isBreakOnPingPong = isCatchPingPong;
        getConfig().setProperty(BREAK_ON_PING_PONG, isCatchPingPong);
    }

    /**
     * If true, then WebSocket messages are caught when <i>break on all requests/responses</i> is
     * active. Otherwise WebSocket communication is skipped.
     *
     * @return True if it should break on all HTTP requests/responses.
     */
    public boolean isBreakOnAll() {
        return isBreakOnAll;
    }

    /**
     * @see OptionsParamWebSocket#isBreakOnAll()
     * @param isBreakOnAll
     */
    public void setBreakOnAll(boolean isBreakOnAll) {
        this.isBreakOnAll = isBreakOnAll;
        getConfig().setProperty(BREAK_ON_ALL, isBreakOnAll);
    }

    public boolean isConfirmRemoveProxyExcludeRegex() {
        return this.confirmRemoveProxyExcludeRegex;
    }

    public void setConfirmRemoveProxyExcludeRegex(boolean confirmRemove) {
        this.confirmRemoveProxyExcludeRegex = confirmRemove;
        getConfig()
                .setProperty(
                        CONFIRM_REMOVE_PROXY_EXCLUDE_REGEX_KEY, Boolean.valueOf(confirmRemove));
    }

    /**
     * Sets whether or not the header {@code Sec-WebSocket-Extensions} should be removed from the
     * handshake messages.
     *
     * @param remove {@code true} if the header should be removed, {@code false} otherwise
     * @see #isRemoveExtensionsHeader()
     */
    public void setRemoveExtensionsHeader(boolean remove) {
        if (removeExtensionsHeader != remove) {
            this.removeExtensionsHeader = remove;
            getConfig()
                    .setProperty(
                            REMOVE_EXTENSIONS_HEADER_KEY, Boolean.valueOf(removeExtensionsHeader));
        }
    }

    /**
     * Tells whether or not the header {@code Sec-WebSocket-Extensions} should be removed from the
     * handshake messages.
     *
     * <p>When enabled it allows ZAP to properly process the WebSocket messages, as no further (and
     * unsupported) transformation is done to them (for example, compression).
     *
     * @return {@code true} if the header should be removed, {@code false} otherwise
     * @see #setRemoveExtensionsHeader(boolean)
     */
    public boolean isRemoveExtensionsHeader() {
        return removeExtensionsHeader;
    }
}
