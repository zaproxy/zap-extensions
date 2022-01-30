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

import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** Default implementation of {@link HttpMessageHandlerContext}. */
class DefaultHttpMessageHandlerContext implements HttpMessageHandlerContext {

    private boolean recursive;
    private boolean fromClient;
    private boolean excluded;
    private boolean overridden;
    private boolean close;

    /** Constructs a {@code DefaultHttpMessageHandlerContext} with default state. */
    DefaultHttpMessageHandlerContext() {
        reset();
    }

    /**
     * Resets the context to default state, ready for the handling of a request.
     *
     * @see #handlingResponse()
     */
    void reset() {
        recursive = false;
        excluded = false;
        fromClient = true;
        overridden = false;
        close = false;
    }

    /** Changes the state for the handling of a response. */
    void handlingResponse() {
        fromClient = false;
        overridden = false;
        close = false;
    }

    @Override
    public boolean isRecursive() {
        return recursive;
    }

    void setRecursive(boolean recursive) {
        this.recursive = recursive;
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
