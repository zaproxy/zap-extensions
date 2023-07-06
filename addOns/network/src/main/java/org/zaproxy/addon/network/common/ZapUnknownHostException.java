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
package org.zaproxy.addon.network.common;

import java.net.UnknownHostException;

/**
 * An {@code UnknownHostException} that provides additional information of ZAP's state.
 *
 * @since 0.3.0
 */
public class ZapUnknownHostException extends UnknownHostException {

    private static final long serialVersionUID = 1L;

    private final boolean fromOutgoingProxy;

    /**
     * Constructs a {@code ZapUnknownHostException} with the given host and whether the host is the
     * outgoing proxy.
     *
     * @param host the name of the host.
     * @param fromOutgoingProxy {@code true} if failed to resolve the outgoing proxy's host, {@code
     *     false} otherwise.
     * @deprecated (0.10.0) Use {@link #ZapUnknownHostException(UnknownHostException, boolean)}
     *     instead.
     */
    @Deprecated(since = "0.10.0", forRemoval = true)
    public ZapUnknownHostException(String host, boolean fromOutgoingProxy) {
        super(host);

        this.fromOutgoingProxy = fromOutgoingProxy;
    }

    /**
     * Constructs a {@code ZapUnknownHostException} with the given exception and whether the host is
     * the outgoing proxy.
     *
     * @param e the original exception.
     * @param fromOutgoingProxy {@code true} if failed to resolve the outgoing proxy's host, {@code
     *     false} otherwise.
     * @throws NullPointerException if the given exception is {@code null}.
     * @since 0.10.0
     */
    public ZapUnknownHostException(UnknownHostException e, boolean fromOutgoingProxy) {
        super(e.getMessage());

        this.fromOutgoingProxy = fromOutgoingProxy;
        setStackTrace(e.getStackTrace());
    }

    /**
     * Tells whether or not the failure happened while resolving the outgoing proxy's host.
     *
     * @return {@code true} if failed to resolve the outgoing proxy's host, {@code false} otherwise.
     */
    public boolean isFromOutgoingProxy() {
        return fromOutgoingProxy;
    }
}
