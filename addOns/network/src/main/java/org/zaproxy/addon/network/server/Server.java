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

import java.io.Closeable;
import java.io.IOException;

/**
 * A server, that can be started and stopped.
 *
 * @since 0.1.0
 */
public interface Server extends Closeable {

    /** The default address the server will bind to. */
    static final String DEFAULT_ADDRESS = "127.0.0.1";

    /** The default port, dynamically assigned. */
    static final int ANY_PORT = 0;

    /** The value of the maximum port. */
    static final int MAX_PORT = 65535;

    /**
     * Starts the server on the given port.
     *
     * @param port the port.
     * @return the port the server is listening to.
     * @throws IllegalArgumentException if the port is invalid.
     * @throws IOException if an error occurred while starting the server.
     */
    default int start(int port) throws IOException {
        return start(DEFAULT_ADDRESS, port);
    }

    /**
     * Starts the server on the given address using a dynamic port.
     *
     * @param address the address.
     * @return the port the server is listening to.
     * @throws IllegalArgumentException if the port is invalid.
     * @throws IOException if an error occurred while starting the server.
     */
    default int start(String address) throws IOException {
        return start(address, ANY_PORT);
    }

    /**
     * Starts the server on the given address and port.
     *
     * @param address the address.
     * @param port the port.
     * @return the port the server is listening to.
     * @throws IllegalArgumentException if the port is invalid.
     * @throws IOException if an error occurred while starting the server.
     */
    int start(String address, int port) throws IOException;

    /**
     * Stops the server and all active connections.
     *
     * @throws IOException if an error occurred while stopping the server.
     */
    void stop() throws IOException;

    /**
     * Validates that the given port is within the allowed range.
     *
     * @param port the port to validate
     * @return the valid port.
     * @throws IllegalArgumentException if the port is invalid.
     */
    static int validatePort(int port) {
        if (port < ANY_PORT || port > MAX_PORT) {
            throw new IllegalArgumentException("Invalid port: " + port);
        }
        return port;
    }
}
