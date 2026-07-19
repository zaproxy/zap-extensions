/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.dev;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.dev.auth.certAuth.CertAuthDir;
import org.zaproxy.addon.dev.error.LoggedErrorsHandler;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionDev extends ExtensionAdaptor {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionDev.class);

    public static final String NAME = "ExtensionDev";

    protected static final String PREFIX = "dev";

    public static final String DIRECTORY_NAME = "dev-add-on";

    private final LoggedErrorsHandler loggedErrorsHandler;

    private TestProxyServer tutorialServer;
    private Server certAuthServer;
    private AltDomainListener altDomainListener = new AltDomainListener();

    private DevParam devParam;

    public ExtensionDev() {
        super(NAME);

        loggedErrorsHandler = new LoggedErrorsHandler();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        loggedErrorsHandler.hook(extensionHook);

        extensionHook.addOptionsParamSet(this.getDevParam());
        extensionHook.addHttpSenderListener(altDomainListener);

        if (Constant.isDevMode()) {
            ExtensionNetwork extensionNetwork =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionNetwork.class);
            tutorialServer = new TestProxyServer(this, extensionNetwork);

            X509TrustManager trustManager = generateClientCertAndTrustManager();
            if (trustManager != null) {
                TestDirectory stubAuthDir = new TestDirectory(tutorialServer, "auth");
                CertAuthDir certAuthDir = new CertAuthDir(tutorialServer, "cert-auth");
                stubAuthDir.addDirectory(certAuthDir);

                certAuthServer =
                        extensionNetwork.createHttpServer(
                                HttpServerConfig.builder()
                                        .setHttpMessageHandler(certAuthDir)
                                        .setTrustManager(trustManager)
                                        .build());
            }

            extensionHook.addApiImplementor(new DevApi());
        }

        if (hasView()) {
            ZapMenuItem menuGarbageCollect = new ZapMenuItem("dev.tools.menu.gc");
            menuGarbageCollect.addActionListener(e -> Runtime.getRuntime().gc());
            extensionHook.getHookMenu().addToolsMenuItem(menuGarbageCollect);
        }
    }

    public DevParam getDevParam() {
        if (devParam == null) {
            devParam = new DevParam();
        }
        return devParam;
    }

    public void addDomainListener(String domain, HttpSenderListener listener) {
        this.altDomainListener.addDomainListener(domain, listener);
    }

    @Override
    public void optionsLoaded() {
        if (tutorialServer != null) {
            tutorialServer.start();
        }
        if (certAuthServer != null) {
            try {
                certAuthServer.start(getDevParam().getTestHost(), CertAuthDir.DEFAULT_PORT);
            } catch (IOException e) {
                LOGGER.warn("Failed to start certificate auth test server.", e);
            }
        }
    }

    @Override
    public void unload() {
        if (tutorialServer != null) {
            tutorialServer.stop();
        }
        if (certAuthServer != null) {
            try {
                certAuthServer.stop();
            } catch (IOException e) {
                LOGGER.debug("Error stopping cert auth server.", e);
            }
        }

        loggedErrorsHandler.unload();
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    /**
     * Generates a fresh CA and client certificate on each startup, writes the client certificate to
     * {@code test-client.p12} in ZAP's home directory, and returns a {@link X509TrustManager} that
     * trusts the generated CA.
     */
    private X509TrustManager generateClientCertAndTrustManager() {
        Security.addProvider(new BouncyCastleProvider());
        try {
            long now = System.currentTimeMillis();
            Date notBefore = new Date(now - Duration.ofDays(1).toMillis());

            // Generate CA keypair and self-signed CA cert (valid 10 years).
            KeyPair caKeyPair = generateRsaKeyPair();
            X500Name caName = new X500Name("CN=ZAP Dev Test CA, O=ZAP, C=xx");
            JcaX509v3CertificateBuilder caCertBuilder =
                    new JcaX509v3CertificateBuilder(
                            caName,
                            BigInteger.ONE,
                            notBefore,
                            new Date(now + Duration.ofDays(3650).toMillis()),
                            caName,
                            caKeyPair.getPublic());
            caCertBuilder.addExtension(
                    Extension.basicConstraints, true, new BasicConstraints(true));
            caCertBuilder.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            X509Certificate caCert = signCert(caCertBuilder, caKeyPair.getPrivate());

            // Generate client keypair and cert signed by CA (valid 2 years).
            KeyPair clientKeyPair = generateRsaKeyPair();
            X500Name clientName = new X500Name("CN=ZAP Dev Test Client, O=ZAP, C=xx");
            JcaX509v3CertificateBuilder clientCertBuilder =
                    new JcaX509v3CertificateBuilder(
                            caName,
                            BigInteger.valueOf(2),
                            notBefore,
                            new Date(now + Duration.ofDays(730).toMillis()),
                            clientName,
                            clientKeyPair.getPublic());
            clientCertBuilder.addExtension(
                    Extension.basicConstraints, false, new BasicConstraints(false));
            clientCertBuilder.addExtension(
                    Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            clientCertBuilder.addExtension(
                    Extension.extendedKeyUsage,
                    false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
            X509Certificate clientCert = signCert(clientCertBuilder, caKeyPair.getPrivate());

            // Write client cert + key to test-client.p12 in ZAP's home directory.
            Path clientCertFile =
                    Path.of(
                            Constant.getZapHome(),
                            DIRECTORY_NAME,
                            "auth",
                            "cert-auth",
                            "test-client.p12");
            Files.createDirectories(clientCertFile.getParent());
            char[] password = CertAuthDir.CERT_PASSWORD.toCharArray();
            KeyStore clientKeyStore = KeyStore.getInstance("PKCS12");
            clientKeyStore.load(null, null);
            clientKeyStore.setKeyEntry(
                    "test-client",
                    clientKeyPair.getPrivate(),
                    password,
                    new Certificate[] {clientCert, caCert});
            try (OutputStream os = Files.newOutputStream(clientCertFile)) {
                clientKeyStore.store(os, password);
            }

            // Write the CA cert in PEM format so users can install it in their browser.
            Path caCertFile = clientCertFile.getParent().resolve("ca.crt");
            String pemCert =
                    "-----BEGIN CERTIFICATE-----\n"
                            + Base64.getMimeEncoder(64, new byte[] {'\n'})
                                    .encodeToString(caCert.getEncoded())
                            + "\n-----END CERTIFICATE-----\n";
            Files.writeString(caCertFile, pemCert, StandardCharsets.US_ASCII);

            // Build a TrustManager from the CA cert for the server to validate client certs.
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);
            trustStore.setCertificateEntry("ca", caCert);
            TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    return (X509TrustManager) tm;
                }
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to generate test client certificate:", e);
        }
        return null;
    }

    private static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048, new SecureRandom());
        return gen.generateKeyPair();
    }

    private static X509Certificate signCert(JcaX509v3CertificateBuilder builder, PrivateKey key)
            throws OperatorCreationException, CertificateException {
        ContentSigner signer =
                new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(key);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }
}
