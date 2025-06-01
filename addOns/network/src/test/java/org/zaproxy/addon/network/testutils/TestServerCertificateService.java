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
package org.zaproxy.addon.network.testutils;

import java.security.KeyStore;
import org.zaproxy.addon.network.ServerCertificatesOptions;
import org.zaproxy.addon.network.internal.cert.CertData;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
import org.zaproxy.addon.network.internal.cert.GenerationException;
import org.zaproxy.addon.network.internal.cert.ServerCertificateGenerator;
import org.zaproxy.addon.network.internal.cert.ServerCertificateService;

/**
 * A {@link ServerCertificateService} for tests.
 *
 * @see #createInstance()
 */
public class TestServerCertificateService implements ServerCertificateService {

    private final ServerCertificatesOptions serverCertificatesOptions;
    private ServerCertificateGenerator generator;

    public static TestServerCertificateService createInstance() {
        ServerCertificatesOptions serverCertificatesOptions = new ServerCertificatesOptions();
        KeyStore rootCa =
                CertificateUtils.createRootCaKeyStore(
                        serverCertificatesOptions.getRootCaCertConfig());
        TestServerCertificateService certificateService =
                new TestServerCertificateService(serverCertificatesOptions);
        certificateService.setRootCa(rootCa);
        return certificateService;
    }

    TestServerCertificateService(ServerCertificatesOptions serverCertificatesOptions) {
        this.serverCertificatesOptions = serverCertificatesOptions;
    }

    public void setRootCa(KeyStore keyStore) {
        generator = new ServerCertificateGenerator(keyStore, serverCertificatesOptions);
    }

    @Override
    public KeyStore createCertificate(CertData certData) throws GenerationException {
        if (generator == null) {
            throw new GenerationException("The root CA certificate was not set.");
        }
        return generator.generate(certData);
    }
}
