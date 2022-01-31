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

import java.io.IOException;
import java.security.KeyStore;
import org.parosproxy.paros.security.CertData;
import org.parosproxy.paros.security.MissingRootCertificateException;
import org.parosproxy.paros.security.SslCertificateService;
import org.zaproxy.addon.network.ServerCertificatesOptions;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
import org.zaproxy.addon.network.internal.cert.GenerationException;
import org.zaproxy.addon.network.internal.cert.ServerCertificateGenerator;

/**
 * A {@link SslCertificateService} for tests.
 *
 * @see #createInstance()
 */
public class TestSslCertificateService implements SslCertificateService {

    private final ServerCertificatesOptions serverCertificatesOptions;
    private ServerCertificateGenerator generator;

    public static TestSslCertificateService createInstance() {
        ServerCertificatesOptions serverCertificatesOptions = new ServerCertificatesOptions();
        KeyStore rootCa =
                CertificateUtils.createRootCaKeyStore(
                        serverCertificatesOptions.getRootCaCertConfig());
        TestSslCertificateService sslCertificateService =
                new TestSslCertificateService(serverCertificatesOptions);
        sslCertificateService.initializeRootCA(rootCa);
        return sslCertificateService;
    }

    TestSslCertificateService(ServerCertificatesOptions serverCertificatesOptions) {
        this.serverCertificatesOptions = serverCertificatesOptions;
    }

    @Override
    public void initializeRootCA(KeyStore keyStore) {
        generator = new ServerCertificateGenerator(keyStore, serverCertificatesOptions);
    }

    @Override
    public KeyStore createCertForHost(String hostname) {
        return null;
    }

    @Override
    public KeyStore createCertForHost(CertData certData) throws IOException {
        if (generator == null) {
            throw new MissingRootCertificateException("The root CA certificate was not set.");
        }

        try {
            return generator.generate(certData);
        } catch (GenerationException e) {
            throw new IOException(e);
        }
    }
}
