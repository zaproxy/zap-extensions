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
package org.zaproxy.addon.network.internal.client;

import java.net.PasswordAuthentication;
import java.util.Arrays;
import java.util.Objects;

/**
 * A HTTP proxy.
 *
 * <p>Contains the host, port, realm, and password authentication.
 */
public class HttpProxy {

    private final String host;
    private final int port;
    private final String realm;
    private final PasswordAuthentication passwordAuthentication;

    /**
     * Constructs a {@code SocksProxy} with the given data.
     *
     * @param host the host, must not be {@code null} or empty.
     * @param port the port.
     * @param realm the realm of the HTTP proxy, must not be {@code null}.
     * @param passwordAuthentication the password authentication, must not be {@code null}.
     * @throws NullPointerException if the {@code host} or {@code passwordAuthentication} is {@code
     *     null}.
     * @throws IllegalArgumentException if the {@code host} is empty or the {@code port} is not a
     *     valid port number.
     */
    public HttpProxy(
            String host, int port, String realm, PasswordAuthentication passwordAuthentication) {
        Objects.requireNonNull(host, "The host must not be null.");
        Objects.requireNonNull(realm, "The realm must not be null.");
        Objects.requireNonNull(
                passwordAuthentication, "The password authentication must not be null.");
        if (host.isEmpty()) {
            throw new IllegalArgumentException("The host must not be empty.");
        }
        if (port <= 0 || port > 65535) {
            throw new IllegalArgumentException(
                    "The port is not valid, must be between 0 and 65535.");
        }
        this.host = host;
        this.port = port;
        this.realm = realm;
        this.passwordAuthentication = passwordAuthentication;
    }

    /**
     * Gets the host (name or address).
     *
     * @return the host, never {@code null} or empty.
     */
    public String getHost() {
        return host;
    }

    /**
     * Gets the port.
     *
     * @return the port.
     */
    public int getPort() {
        return port;
    }

    /**
     * Gets the realm.
     *
     * @return the realm, never {@code null}.
     */
    public String getRealm() {
        return realm;
    }

    /**
     * Gets the password authentication.
     *
     * @return the password authentication, never {@code null}.
     */
    public PasswordAuthentication getPasswordAuthentication() {
        return passwordAuthentication;
    }

    @Override
    public int hashCode() {
        return hashCode(
                host,
                port,
                passwordAuthentication.getUserName(),
                passwordAuthentication.getPassword());
    }

    private static int hashCode(Object... values) {
        return Arrays.deepHashCode(values);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof HttpProxy)) {
            return false;
        }
        HttpProxy other = (HttpProxy) obj;
        return Objects.equals(host, other.host)
                && port == other.port
                && Objects.equals(realm, other.realm)
                && Objects.equals(
                        passwordAuthentication.getUserName(),
                        other.passwordAuthentication.getUserName())
                && Arrays.equals(
                        passwordAuthentication.getPassword(),
                        other.passwordAuthentication.getPassword());
    }

    @Override
    public String toString() {
        StringBuilder strBuilder = new StringBuilder(75);
        strBuilder.append("[Host=").append(host);
        strBuilder.append(", Port=").append(port);
        strBuilder.append(", Realm=").append(realm);
        strBuilder.append(", UserName=").append(passwordAuthentication.getUserName());
        strBuilder.append(", Password=***");
        strBuilder.append(']');
        return strBuilder.toString();
    }
}
