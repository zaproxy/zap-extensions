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

import java.net.SocketTimeoutException;

/**
 * A {@code SocketTimeoutException} that provides additional information of ZAP's state.
 *
 * @since 0.3.0
 */
public class ZapSocketTimeoutException extends SocketTimeoutException {

    private static final long serialVersionUID = 1L;

    private final int timeout;

    /**
     * Constructs a {@code ZapSocketTimeoutException} with the given detail message and the value of
     * the timeout.
     *
     * @param msg the detail message.
     * @param timeout the value of the timeout.
     * @deprecated (0.10.0) Use {@link #ZapSocketTimeoutException(SocketTimeoutException, int)}
     *     instead.
     */
    @Deprecated(since = "0.10.0", forRemoval = true)
    public ZapSocketTimeoutException(String msg, int timeout) {
        super(msg);

        this.timeout = timeout;
    }

    /**
     * Constructs a {@code ZapSocketTimeoutException} with the given exception and the value of the
     * timeout.
     *
     * @param e the original exception.
     * @param timeout the value of the timeout.
     * @throws NullPointerException if the given exception is {@code null}.
     * @since 0.10.0
     */
    public ZapSocketTimeoutException(SocketTimeoutException e, int timeout) {
        super(e.getMessage());

        this.timeout = timeout;
        setStackTrace(e.getStackTrace());
    }

    /**
     * Gets the value of the timeout.
     *
     * @return the value of the timeout.
     */
    public int getTimeout() {
        return timeout;
    }
}
