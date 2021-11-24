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
package org.zaproxy.addon.network;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.security.SslCertificateService;
import org.zaproxy.zap.extension.dynssl.DynSSLParam;

public class ExtensionNetwork extends ExtensionAdaptor {

    private static final String I18N_PREFIX = "network";

    public ExtensionNetwork() {
        super(ExtensionNetwork.class.getSimpleName());

        setI18nPrefix(I18N_PREFIX);
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("network.ext.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("network.ext.desc");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    /**
     * Writes the Root CA certificate to the specified file in PEM format, suitable for importing
     * into browsers.
     *
     * @param path the path the Root CA certificate will be written to.
     * @throws IOException if an error occurred while writing the certificate.
     */
    public void writeRootCaCertAsPem(Path path) throws IOException {
        DynSSLParam param = Model.getSingleton().getOptionsParam().getParamSet(DynSSLParam.class);
        KeyStore ks = param.getRootca();
        if (ks == null) {
            return;
        }

        try {
            Certificate cert = ks.getCertificate(SslCertificateService.ZAPROXY_JKS_ALIAS);
            try (Writer w = Files.newBufferedWriter(path, StandardCharsets.US_ASCII);
                    PemWriter pw = new PemWriter(w)) {
                pw.writeObject(new JcaMiscPEMGenerator(cert));
                pw.flush();
            }
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}
