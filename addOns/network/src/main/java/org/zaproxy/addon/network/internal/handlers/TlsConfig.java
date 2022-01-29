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

    private List<String> enabledProtocols;

    /** Constructs a {@code TlsConfig} with all the SSL/TLS protocol versions supported. */
    public TlsConfig() {
        this.enabledProtocols = TlsUtils.filterUnsupportedProtocols(DEFAULT_PROTOCOLS);
    }

    /**
     * Constructs a {@code TlsConfig} with the given SSL/TLS protocol versions.
     *
     * @param enabledProtocols the enabled protocols
     * @throws IllegalArgumentException if no protocol is provided or none supported.
     * @throws NullPointerException if the given {@code enabledProtocols} is {@code null}.
     */
    public TlsConfig(List<String> enabledProtocols) {
        this.enabledProtocols = TlsUtils.filterUnsupportedProtocols(enabledProtocols);
    }

    /**
     * Gets the enabled protocols.
     *
     * @return a list with the enabled protocols.
     */
    public List<String> getEnabledProtocols() {
        return enabledProtocols;
    }

    @Override
    public int hashCode() {
        return Objects.hash(enabledProtocols);
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
        return Objects.equals(enabledProtocols, other.enabledProtocols);
    }
}
