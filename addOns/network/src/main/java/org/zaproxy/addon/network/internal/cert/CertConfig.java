/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.cert;

import java.time.Duration;
import java.util.Objects;
import org.apache.commons.lang3.StringUtils;

/** Configuration to generate certificates. */
public class CertConfig {

    private Duration validity;
    private String crlDistributionPoint;

    /**
     * Constructs a {@code CertConfig} with the given validity.
     *
     * @param validity the validity.
     * @throws NullPointerException if the given validity is {@code null}.
     */
    public CertConfig(Duration validity) {
        this(validity, null);
    }

    /**
     * Constructs a {@code CertConfig} with the given validity and CRL distribution point.
     *
     * @param validity the validity duration.
     * @param crlDistributionPoint the URL for the CRL.
     * @throws NullPointerException if the given validity is {@code null}.
     */
    public CertConfig(Duration validity, String crlDistributionPoint) {
        this.validity = Objects.requireNonNull(validity);
        this.crlDistributionPoint =
                StringUtils.isBlank(crlDistributionPoint) ? null : crlDistributionPoint;
    }

    /**
     * The validity of the certificate.
     *
     * @return the validity, never {@code null}.
     */
    public Duration getValidity() {
        return validity;
    }

    /**
     * The URL for the Certificate Revocation List Distribution Point.
     *
     * @return the URL, or {@code null} if none.
     */
    public String getCrlDistributionPoint() {
        return crlDistributionPoint;
    }
}
