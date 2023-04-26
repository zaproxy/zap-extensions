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
package org.zaproxy.addon.network.internal.server.http;

import io.netty.channel.Channel;
import java.util.Objects;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** Default implementation of {@link HttpMessageHandlerContext}. */
class DefaultHttpMessageHandlerContext implements HttpMessageHandlerContext {

    private final Channel channel;
    private final RecursiveRequestChecker recursiveRequestChecker;
    private boolean recursive;
    private boolean fromClient;
    private boolean excluded;
    private boolean overridden;
    private boolean close;

    /**
     * Constructs a {@code DefaultHttpMessageHandlerContext} with default state.
     *
     * @param channel the channel.
     * @param recursiveRequestChecker
     */
    DefaultHttpMessageHandlerContext(
            Channel channel, RecursiveRequestChecker recursiveRequestChecker) {
        this.channel = Objects.requireNonNull(channel);
        this.recursiveRequestChecker = Objects.requireNonNull(recursiveRequestChecker);
        fromClient = true;
    }

    /**
     * Changes the state for the handling of a response.
     *
     * <p>It also updates the recursive state, the last time.
     *
     * @see #updateRecursiveState(HttpMessage)
     */
    void handlingResponse(HttpMessage msg) {
        updateRecursiveState(msg);

        fromClient = false;
        overridden = false;
        close = false;
    }

    /**
     * Updates the recursive state for the given message.
     *
     * <p>The recursive state is not updated if already handling the response.
     *
     * @param msg the message to check.
     * @see #handlingResponse(HttpMessage)
     */
    void updateRecursiveState(HttpMessage msg) {
        if (fromClient) {
            recursive = recursiveRequestChecker.isRecursive(channel, msg);
        }
    }

    @Override
    public boolean isRecursive() {
        return recursive;
    }

    @Override
    public boolean isFromClient() {
        return fromClient;
    }

    boolean isOverridden() {
        return overridden;
    }

    @Override
    public void overridden() {
        this.overridden = true;
    }

    boolean isClose() {
        return close;
    }

    @Override
    public void close() {
        close = true;
    }

    @Override
    public boolean isExcluded() {
        return excluded;
    }

    void setExcluded(boolean excluded) {
        this.excluded = excluded;
    }
}
