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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Objects;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.handlers.TlsConfig;
import org.zaproxy.addon.network.internal.server.AliasChecker;
import org.zaproxy.addon.network.internal.server.ServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.utils.Enableable;

/** The configuration of a local server/proxy, ones managed by the user. */
public class LocalServerConfig extends Enableable implements ServerConfig {

    /** The default address. */
    public static final String DEFAULT_ADDRESS = "localhost";

    /** The default address used when empty. */
    public static final String DEFAULT_ANY_ADDRESS = "0.0.0.0";

    /** The default port. */
    public static final int DEFAULT_PORT = 8080;

    /** The mode in how the local server behaves. */
    public enum ServerMode {
        /** If both the API and proxy should be enabled. */
        API_AND_PROXY(true, true),
        /** If only the API should be enabled. */
        API(true, false),
        /** If only the proxy should be enabled. */
        PROXY(false, true);

        private final boolean api;
        private final boolean proxy;

        ServerMode(boolean api, boolean proxy) {
            this.api = api;
            this.proxy = proxy;
        }

        /**
         * Tells whether or not this mode has the API enabled.
         *
         * @return {@code true} if the API is enabled, {@code false} otherwise.
         */
        public boolean hasApi() {
            return api;
        }

        /**
         * Tells whether or not this mode has the proxy enabled.
         *
         * @return {@code true} if the proxy is enabled, {@code false} otherwise.
         */
        public boolean hasProxy() {
            return proxy;
        }
    }

    private ServerMode mode;
    private String address;
    private boolean anyLocalAddress;
    private int port;
    private List<String> tlsProtocols;
    private TlsConfig tlsConfig;
    private boolean behindNat;
    private boolean removeAcceptEncoding;
    private boolean decodeResponse;
    private AliasChecker aliasChecker;

    /** Constructs a {@code LocalServerConfig} with the defaults. */
    public LocalServerConfig() {
        address = DEFAULT_ADDRESS;
        port = DEFAULT_PORT;
        mode = ServerMode.API_AND_PROXY;
        setTlsProtocols(TlsUtils.getSupportedProtocols());
        removeAcceptEncoding = true;
        decodeResponse = true;
        setEnabled(true);
    }

    /**
     * Constructs a {@code LocalServerConfig} from the given instance.
     *
     * @param other another instance with the data.
     * @throws NullPointerException if the given instance is {@code null}.
     */
    public LocalServerConfig(LocalServerConfig other) {
        Objects.requireNonNull(other);
        updateFrom(other);
    }

    /**
     * Constructs a {@code LocalServerConfig} from the given instance and with the given alias
     * checker.
     *
     * @param other another instance with the data.
     * @param aliasChecker the alias checker.
     * @throws NullPointerException if the given instance is {@code null}.
     */
    public LocalServerConfig(LocalServerConfig other, AliasChecker aliasChecker) {
        this(other);
        this.aliasChecker = aliasChecker;
    }

    /**
     * Updates this instance with the data from the given one.
     *
     * @param other another instance with the data.
     * @return {@code true} if the address/port has changed, {@code false} otherwise.
     * @throws NullPointerException if the given instance is {@code null}.
     */
    public boolean updateFrom(LocalServerConfig other) {
        Objects.requireNonNull(other);
        setEnabled(other.isEnabled());
        boolean requiresRestart = port != other.port || !Objects.equals(address, other.address);
        address = other.address;
        anyLocalAddress = other.anyLocalAddress;
        mode = other.mode;
        port = other.port;
        setTlsProtocols(other.getTlsProtocols());
        behindNat = other.behindNat;
        removeAcceptEncoding = other.removeAcceptEncoding;
        decodeResponse = other.decodeResponse;
        return requiresRestart;
    }

    /**
     * Sets the mode of the server.
     *
     * @param mode the mode of the server.
     * @throws NullPointerException if the given mode is {@code null}.
     */
    public void setMode(ServerMode mode) {
        this.mode = Objects.requireNonNull(mode);
    }

    /**
     * Gets the mode of the server.
     *
     * @return the mode of the server, never {@code null}.
     */
    public ServerMode getMode() {
        return mode;
    }

    /**
     * Tells whether or not the API is enabled.
     *
     * @return {@code true} if the API is enabled, {@code false} otherwise.
     */
    public boolean isApiEnabled() {
        return mode.hasApi();
    }

    /**
     * Gets the address of the server.
     *
     * @return the address of the server.
     */
    public String getAddress() {
        return address;
    }

    /**
     * Sets the address of the server.
     *
     * <p>If the address is empty it is assumed to be "any address".
     *
     * @param address the address of the server.
     * @throws NullPointerException if the given address is {@code null}.
     */
    public void setAddress(String address) {
        Objects.requireNonNull(address);

        if (address.isEmpty()) {
            this.address = LocalServerConfig.DEFAULT_ANY_ADDRESS;
            this.anyLocalAddress = true;
        } else {
            this.address = address;
            this.anyLocalAddress = isAnyLocalAddress(address);
        }
    }

    @Override
    public boolean isAnyLocalAddress() {
        return anyLocalAddress;
    }

    /**
     * Gets the port of the server.
     *
     * @return the port of the server.
     */
    public int getPort() {
        return port;
    }

    /**
     * Sets the port of the server.
     *
     * @param port the port of the server.
     * @throws IllegalArgumentException if the port is invalid.
     */
    public void setPort(int port) {
        Server.validatePort(port);
        this.port = port;
    }

    /**
     * Gets the SSL/TLS protocols of the server.
     *
     * @return the SSL/TLS protocols of the server.
     */
    public List<String> getTlsProtocols() {
        return tlsProtocols;
    }

    /**
     * Sets the SSL/TLS protocols of the server.
     *
     * @param tlsProtocols the SSL/TLS protocols of the server.
     * @throws IllegalArgumentException if no protocol is provided or none supported.
     * @throws NullPointerException if the given list is {@code null}.
     */
    public void setTlsProtocols(List<String> tlsProtocols) {
        this.tlsProtocols = Objects.requireNonNull(tlsProtocols);
        this.tlsConfig = new TlsConfig(tlsProtocols);
    }

    /**
     * Gets the {@link TlsConfig}.
     *
     * @return the config, never {@code null}.
     */
    public TlsConfig getTlsConfig() {
        return tlsConfig;
    }

    @Override
    public boolean isBehindNat() {
        return behindNat;
    }

    /**
     * Sets whether or not the server is behind NAT.
     *
     * @param behindNat {@code true} if the server is behind NAT, {@code false} otherwise.
     */
    public void setBehindNat(boolean behindNat) {
        this.behindNat = behindNat;
    }

    /**
     * Tells whether or not the server should remove the Accept-Encoding header.
     *
     * @return {@code true} if the server should remove the header, {@code false} otherwise.
     */
    public boolean isRemoveAcceptEncoding() {
        return removeAcceptEncoding;
    }

    /**
     * Sets whether or not the server should remove the Accept-Encoding header.
     *
     * @param removeAcceptEncoding {@code true} if the server should remove the header, {@code
     *     false} otherwise.
     */
    public void setRemoveAcceptEncoding(boolean removeAcceptEncoding) {
        this.removeAcceptEncoding = removeAcceptEncoding;
    }

    /**
     * Tells whether or not the server should decode the response.
     *
     * @return {@code true} if the server should decode the response, {@code false} otherwise.
     */
    public boolean isDecodeResponse() {
        return decodeResponse;
    }

    /**
     * Sets whether or not the server should decode the response.
     *
     * @param decodeResponse {@code true} if the server should decode the response, {@code false}
     *     otherwise.
     */
    public void setDecodeResponse(boolean decodeResponse) {
        this.decodeResponse = decodeResponse;
    }

    @Override
    public boolean isAlias(HttpRequestHeader header) {
        return aliasChecker != null && aliasChecker.isAlias(header);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result =
                prime * result
                        + Objects.hash(
                                address,
                                behindNat,
                                decodeResponse,
                                mode,
                                port,
                                removeAcceptEncoding,
                                tlsProtocols);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (!(obj instanceof LocalServerConfig)) {
            return false;
        }
        LocalServerConfig other = (LocalServerConfig) obj;
        return Objects.equals(address, other.address)
                && behindNat == other.behindNat
                && decodeResponse == other.decodeResponse
                && mode == other.mode
                && port == other.port
                && removeAcceptEncoding == other.removeAcceptEncoding
                && Objects.equals(tlsProtocols, other.tlsProtocols);
    }

    private static boolean isAnyLocalAddress(String address) {
        try {
            return InetAddress.getByName(address).isAnyLocalAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }
}
