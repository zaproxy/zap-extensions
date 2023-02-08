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
package org.zaproxy.addon.network.internal.handlers;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.zaproxy.addon.network.internal.TlsUtils;

/** The configuration for {@link TlsProtocolHandler}. */
public class TlsConfig {

    private static final List<String> DEFAULT_PROTOCOLS =
            Arrays.asList(
                    TlsUtils.SSL_V3,
                    TlsUtils.TLS_V1,
                    TlsUtils.TLS_V1_1,
                    TlsUtils.TLS_V1_2,
                    TlsUtils.TLS_V1_3);

    private static final List<String> DEFAULT_APPLICATION_PROTOCOLS =
            List.of(TlsUtils.APPLICATION_PROTOCOL_HTTP_1_1, TlsUtils.APPLICATION_PROTOCOL_HTTP_2);

    private List<String> tlsProtocols;
    private boolean alpnEnabled;
    private List<String> applicationProtocols;

    /**
     * Constructs a {@code TlsConfig} with all the SSL/TLS protocol versions supported, with ALPN
     * enabled, and with all application protocols.
     *
     * <p>If no protocol is negotiated it falls back to HTTP/1.1.
     */
    public TlsConfig() {
        this(DEFAULT_PROTOCOLS, true, DEFAULT_APPLICATION_PROTOCOLS);
    }

    /**
     * Constructs a {@code TlsConfig} with the given SSL/TLS protocol versions, if ALPN is enabled,
     * and with the given application protocols.
     *
     * @param tlsProtocols the enabled protocols
     * @param alpnEnabled {@code true} if ALPN should be enabled, {@code false} otherwise.
     * @param applicationProtocols the application protocols, if not empty
     * @throws IllegalArgumentException if no protocol is provided or none supported.
     * @throws NullPointerException if the given {@code tlsProtocols} or {@code
     *     applicationProtocols} is {@code null}.
     */
    public TlsConfig(
            List<String> tlsProtocols, boolean alpnEnabled, List<String> applicationProtocols) {
        this.tlsProtocols = TlsUtils.filterUnsupportedTlsProtocols(tlsProtocols);
        this.alpnEnabled = alpnEnabled;
        this.applicationProtocols =
                TlsUtils.filterUnsupportedApplicationProtocols(applicationProtocols);
    }

    /**
     * Gets the TLS protocols.
     *
     * @return a list with the TLS protocols.
     */
    public List<String> getTlsProtocols() {
        return tlsProtocols;
    }

    /**
     * Tells whether or not ALPN is enabled.
     *
     * @return {@code true} if ALPN is enabled, {@code false} otherwise.
     */
    public boolean isAlpnEnabled() {
        return alpnEnabled;
    }

    /**
     * Gets the application protocols to use when ALPN is enabled.
     *
     * @return the application protocols.
     */
    public List<String> getApplicationProtocols() {
        return applicationProtocols;
    }

    @Override
    public int hashCode() {
        return Objects.hash(tlsProtocols, alpnEnabled, applicationProtocols);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof TlsConfig)) {
            return false;
        }
        TlsConfig other = (TlsConfig) object;
        return Objects.equals(tlsProtocols, other.tlsProtocols)
                && alpnEnabled == other.alpnEnabled
                && Objects.equals(applicationProtocols, other.applicationProtocols);
    }
}
