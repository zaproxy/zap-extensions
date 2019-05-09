/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.ui.httppanel;

import java.awt.Component;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;

/**
 * A default implementation of a {@code SingleWebSocketMessageContainer}.
 *
 * @see SingleWebSocketMessageContainer
 */
public class DefaultSingleWebSocketMessageContainer extends AbstractWebSocketMessageContainer
        implements SingleWebSocketMessageContainer {

    private final WebSocketMessageDTO webSocketMessage;

    /**
     * Constructs a {@code DefaultSingleWebSocketMessageContainer} with no contained {@code
     * WebSocketMessage} and with the given container {@code name} and {@code component}.
     *
     * @param name the name of the container
     * @param component the GUI component of the container
     * @throws IllegalArgumentException if the given {@code name} or {@code component} is {@code
     *     null}.
     */
    public DefaultSingleWebSocketMessageContainer(String name, Component component) {
        this(name, component, null);
    }

    /**
     * Constructs a {@code DefaultSingleWebSocketMessageContainer} with the given container {@code
     * name} and {@code component} and contained {@code httpMessage}.
     *
     * @param name the name of the container
     * @param component the GUI component of the container
     * @param webSocketMessage the contained WebSocket message, {@code null} if none
     * @throws IllegalArgumentException if the given {@code name} or {@code component} is {@code
     *     null}.
     */
    public DefaultSingleWebSocketMessageContainer(
            String name, Component component, WebSocketMessageDTO webSocketMessage) {
        super(name, component);
        this.webSocketMessage = webSocketMessage;
    }

    @Override
    public boolean isEmpty() {
        return webSocketMessage == null;
    }

    @Override
    public WebSocketMessageDTO getMessage() {
        return webSocketMessage;
    }
}
