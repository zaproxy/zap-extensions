/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.server;

/**
 * The context for message handlers.
 *
 * <p>Allows to query the state and control how the message is forwarded.
 *
 * @since 0.1.0
 * @see HttpMessageHandler
 */
public interface HttpMessageHandlerContext {

    /**
     * Tells whether or not the message is for the server itself.
     *
     * @return {@code true} if the message is for the server itself, {@code false} otherwise.
     */
    boolean isRecursive();

    /**
     * Tells whether or not the message is excluded.
     *
     * <p>Excluded messages are not meant to be changed in any way while being forwarded.
     *
     * @return {@code true} if the message is excluded, {@code false} otherwise.
     */
    boolean isExcluded();

    /**
     * Tells whether or not the message is from the client.
     *
     * @return {@code true} if the message is from the client, {@code false} otherwise.
     */
    boolean isFromClient();

    /**
     * Indicates that the message contents were overridden and should be forwarded as is.
     *
     * <p>No other handlers will be notified.
     */
    void overridden();

    /**
     * Indicates that the connection should be closed without forwarding the message.
     *
     * <p>No other handlers will be notified.
     */
    void close();
}
