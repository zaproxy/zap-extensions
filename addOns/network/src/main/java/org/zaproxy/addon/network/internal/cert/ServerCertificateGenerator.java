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

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;
import org.parosproxy.paros.security.CertData;
import org.zaproxy.addon.network.ServerCertificatesOptions;

/** A generator of server certificates. */
public class ServerCertificateGenerator {

    private static final AtomicLong serial;

    static {
        Random rnd = new Random();
        rnd.setSeed(System.currentTimeMillis());
        // prevent browser certificate caches, cause of doubled serial numbers
        // using 48bit random number
        long sl = ((long) rnd.nextInt()) << 32 | (rnd.nextInt() & 0xFFFFFFFFL);
        // let reserve of 16 bit for increasing, serials have to be positive
        sl = sl & 0x0000FFFFFFFFFFFFL;
        serial = new AtomicLong(sl);
    }

    private final X509Certificate rootCaCert;
    private final PublicKey rootCaPublicKey;
    private final PrivateKey rooCaPrivateKey;
    private final ServerCertificatesOptions serverCertificatesOptions;
    private final Map<CertData, KeyStore> cache;

    /**
     * Constructs a {@code ServerCertificateGenerator} with the given {@code KeyStore} and options.
     *
     * @param keyStore the {@code KeyStore} containing the root CA certificate.
     * @param serverCertificatesOptions the options to obtain the server configuration.
     * @throws NullPointerException if the given {@code KeyStore} does not contain a certificate nor
     *     the private key, and if the given options are {@code null}.
     */
    public ServerCertificateGenerator(
            KeyStore keyStore, ServerCertificatesOptions serverCertificatesOptions) {
        Objects.requireNonNull(keyStore);
        this.serverCertificatesOptions = Objects.requireNonNull(serverCertificatesOptions);

        rootCaCert = Objects.requireNonNull(CertificateUtils.getCertificate(keyStore));
        rootCaPublicKey = rootCaCert.getPublicKey();
        rooCaPrivateKey = Objects.requireNonNull(CertificateUtils.getPrivateKey(keyStore));

        cache = new HashMap<>();
    }

    /**
     * Generates a server certificate for the given data.
     *
     * @param certData the data of the server.
     * @return the {@code KeyStore} containing the certificate chain, server certificate and root CA
     *     certificate.
     * @throws GenerationException if an error occurred while generating the certificate.
     * @throws NullPointerException if the {@code certData} is null.
     */
    public synchronized KeyStore generate(CertData certData) {
        Objects.requireNonNull(certData);

        return cache.computeIfAbsent(
                certData,
                data ->
                        CertificateUtils.createServerKeyStore(
                                rootCaCert,
                                rootCaPublicKey,
                                rooCaPrivateKey,
                                data,
                                serial.getAndIncrement(),
                                serverCertificatesOptions.getServerCertConfig()));
    }
}
