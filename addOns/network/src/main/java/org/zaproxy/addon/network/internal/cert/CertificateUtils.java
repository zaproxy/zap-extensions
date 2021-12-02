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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.parosproxy.paros.security.CertData;

/** Utilities for certificate generation and manipulation. */
public final class CertificateUtils {

    /**
     * The token that indicates the start of the section that contains the certificate, contained in
     * a {@code .pem} file.
     */
    public static final String BEGIN_CERTIFICATE_TOKEN = "-----BEGIN CERTIFICATE-----";

    /**
     * The token that indicates the end of the section that contains the certificate, contained in a
     * {@code .pem} file.
     */
    public static final String END_CERTIFICATE_TOKEN = "-----END CERTIFICATE-----";

    /**
     * The token that indicates the start of the section that contains the private key, contained in
     * a {@code .pem} file.
     */
    public static final String BEGIN_PRIVATE_KEY_TOKEN = "-----BEGIN PRIVATE KEY-----";

    /**
     * The token that indicates the end of the section that contains the private key, contained in a
     * {@code .pem} file.
     */
    public static final String END_PRIVATE_KEY_TOKEN = "-----END PRIVATE KEY-----";

    static {
        // ExtensionNetwork takes care of removing it when unloaded.
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Logger LOGGER = LogManager.getLogger(CertificateUtils.class);

    /** The passphrase which is used for the Root CA key store. */
    private static final char[] PASSPHRASE = "0w45P.Z4p".toCharArray();

    /** The alias name used in key stores. */
    private static final String ZAPROXY_JKS_ALIAS = "owasp_zap_root_ca";

    /**
     * Constant used to define the start validity date for server certificates. Used as 30d before
     * "now".
     */
    private static final Duration SERVER_CERTIFICATE_START_ADJUSTMENT = Duration.ofDays(30);

    private CertificateUtils() {}

    /**
     * Creates a new Root CA certificate and returns the private and public key in a {@link
     * KeyStore}.
     *
     * @param config the configuration used to generate the certificate.
     * @return the {@code KeyStore} containing the certificate and private key.
     * @throws GenerationException if an error occurred while generating the root CA certificate.
     */
    public static KeyStore createRootCaKeyStore(CertConfig config) {
        try {
            return createRootCaKeyStoreImpl(config);
        } catch (Exception e) {
            throw new GenerationException(
                    "An error occurred while generating the root CA certificate:", e);
        }
    }

    private static KeyStore createRootCaKeyStoreImpl(CertConfig config) throws Exception {
        Date startDate = Calendar.getInstance().getTime();
        Date expireDate = new Date(startDate.getTime() + config.getValidity().toMillis());

        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // using the hash code of the user's name and home path, keeps anonymity
        // but also gives user a chance to distinguish between each other
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, "OWASP Zed Attack Proxy Root CA");
        nameBuilder.addRDN(
                BCStyle.L,
                Integer.toHexString(System.getProperty("user.name").hashCode())
                        + Integer.toHexString(System.getProperty("user.home").hashCode()));
        nameBuilder.addRDN(BCStyle.O, "OWASP Root CA");
        nameBuilder.addRDN(BCStyle.OU, "OWASP ZAP Root CA");
        nameBuilder.addRDN(BCStyle.C, "xx");

        X500Name name = nameBuilder.build();
        X509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        name,
                        BigInteger.valueOf(new Random().nextInt()),
                        startDate,
                        expireDate,
                        name,
                        publicKey);

        try {
            certBuilder.addExtension(
                    Extension.subjectKeyIdentifier,
                    false,
                    new SubjectKeyIdentifier(publicKey.getEncoded()));
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certBuilder.addExtension(
                    Extension.keyUsage,
                    false,
                    new KeyUsage(
                            KeyUsage.keyCertSign
                                    | KeyUsage.digitalSignature
                                    | KeyUsage.keyEncipherment
                                    | KeyUsage.dataEncipherment
                                    | KeyUsage.cRLSign));

            KeyPurposeId[] eku = {
                KeyPurposeId.id_kp_serverAuth,
                KeyPurposeId.id_kp_clientAuth,
                KeyPurposeId.anyExtendedKeyUsage
            };
            certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));

            X509Certificate certificate = createCertificate(privateKey, certBuilder);
            return createKeyStore(privateKey, certificate);
        } catch (Exception e) {
            throw new GenerationException("Errors during assembling root CA.", e);
        }
    }

    private static X509Certificate createCertificate(
            PrivateKey privateKey, X509v3CertificateBuilder certificateBuilder)
            throws OperatorCreationException, CertificateException {
        ContentSigner contentSigner =
                new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(privateKey);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certificateBuilder.build(contentSigner));
    }

    /**
     * Creates a new server certificate and returns the private and public key in a {@link
     * KeyStore}.
     *
     * @param rootCaCert the root CA certificate.
     * @param rootCaPublicKey the public key.
     * @param rootCaPrivateKey the private key.
     * @param certData the data used for the server certificate.
     * @param serial the serial for the server certificate.
     * @param config the configuration used to generate the certificate.
     * @return the {@code KeyStore} containing the certificate and private key.
     * @throws GenerationException if an error occurred while generating the server certificate.
     */
    public static KeyStore createServerKeyStore(
            X509Certificate rootCaCert,
            PublicKey rootCaPublicKey,
            PrivateKey rootCaPrivateKey,
            CertData certData,
            long serial,
            CertConfig config) {
        try {
            return createServerCertificateImpl(
                    rootCaCert, rootCaPublicKey, rootCaPrivateKey, certData, serial, config);
        } catch (Exception e) {
            throw new GenerationException(
                    "An error occurred while generating the server certificate:", e);
        }
    }

    private static KeyStore createServerCertificateImpl(
            X509Certificate rootCaCert,
            PublicKey rootCaPublicKey,
            PrivateKey rootCaPrivateKey,
            CertData certData,
            long serial,
            CertConfig config)
            throws Exception {
        CertData.Name[] certDataNames = certData.getSubjectAlternativeNames();
        GeneralName[] subjectAlternativeNames = new GeneralName[certDataNames.length];
        for (int i = 0; i < certDataNames.length; i++) {
            CertData.Name certDataName = certDataNames[i];
            subjectAlternativeNames[i] =
                    new GeneralName(certDataName.getType(), certDataName.getValue());
        }

        if (certData.getCommonName() == null && subjectAlternativeNames.length == 0) {
            throw new IllegalArgumentException(
                    "commonName is null and no subjectAlternativeNames are specified");
        }

        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        X500NameBuilder namebld = new X500NameBuilder(BCStyle.INSTANCE);
        if (certData.getCommonName() != null) {
            namebld.addRDN(BCStyle.CN, certData.getCommonName());
        }
        namebld.addRDN(BCStyle.OU, "Zed Attack Proxy Project");
        namebld.addRDN(BCStyle.O, "OWASP");
        namebld.addRDN(BCStyle.C, "xx");
        namebld.addRDN(BCStyle.EmailAddress, "zaproxy-develop@googlegroups.com");

        Duration validity = config.getValidity().minus(SERVER_CERTIFICATE_START_ADJUSTMENT);
        long currentTime = System.currentTimeMillis();
        X509v3CertificateBuilder certGen =
                new JcaX509v3CertificateBuilder(
                        new X509CertificateHolder(rootCaCert.getEncoded()).getSubject(),
                        BigInteger.valueOf(serial),
                        new Date(currentTime - SERVER_CERTIFICATE_START_ADJUSTMENT.toMillis()),
                        new Date(currentTime + validity.toMillis()),
                        namebld.build(),
                        publicKey);

        certGen.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                new SubjectKeyIdentifier(publicKey.getEncoded()));
        certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        certGen.addExtension(
                Extension.extendedKeyUsage,
                false,
                new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth}));

        if (subjectAlternativeNames.length > 0) {
            certGen.addExtension(
                    Extension.subjectAlternativeName,
                    certData.isSubjectAlternativeNameIsCritical(),
                    new GeneralNames(subjectAlternativeNames));
        }

        X509Certificate certificate = createCertificate(rootCaPrivateKey, certGen);
        certificate.checkValidity(new Date());
        certificate.verify(rootCaPublicKey);
        return createKeyStore(privateKey, certificate, rootCaCert);
    }

    /**
     * Generates a 2048 bit RSA key pair using SHA1PRNG.
     *
     * @return the key pair
     * @throws NoSuchAlgorithmException if no provider supports the used algorithms.
     */
    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(Long.toString(System.currentTimeMillis()).getBytes());
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048, random);
        return keyGenerator.generateKeyPair();
    }

    private static KeyStore createKeyStore(PrivateKey privateKey, Certificate... certificate)
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        keyStore.setKeyEntry(ZAPROXY_JKS_ALIAS, privateKey, PASSPHRASE, certificate);
        return keyStore;
    }

    /**
     * Stores the given {@code KeyStore} in a Base64 encoded string.
     *
     * @param keyStore the {@code KeyStore}.
     * @return the Base64 encoded string with the {@code KeyStore}.
     * @throws IOException if an error occurred while storing the {@code KeyStore}.
     */
    public static String keyStoreToString(KeyStore keyStore) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            keyStore.store(baos, PASSPHRASE);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
        return Base64.getUrlEncoder().encodeToString(baos.toByteArray());
    }

    /**
     * Reads a {@code KeyStore} from the given Base64 encoded string.
     *
     * @param str the Base64 encoded string with the {@code KeyStore}.
     * @return the {@code KeyStore}, or {@code null} if the given string is {@code null} or empty.
     * @throws IOException if an error occurred while reading the {@code KeyStore}.
     */
    public static KeyStore stringToKeystore(String str) throws IOException {
        if (str == null || str.isEmpty()) {
            return null;
        }

        try {
            byte[] bytes = Base64.getUrlDecoder().decode(str);
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(new ByteArrayInputStream(bytes), PASSPHRASE);
            return keyStore;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * Extracts the certificate from the given {@code .pem} file's contents.
     *
     * @param pem the contents of the {@code .pem} file.
     * @return the certificate, or empty array if the certificate was not found.
     * @throws IllegalArgumentException if the certificate data is not properly {@code base64}
     *     encoded.
     */
    public static byte[] extractCertificate(String pem) {
        return parseDerFromPem(pem, BEGIN_CERTIFICATE_TOKEN, END_CERTIFICATE_TOKEN);
    }

    private static byte[] parseDerFromPem(String pem, String beginDelimiter, String endDelimiter) {
        if (!containsSection(pem, beginDelimiter, endDelimiter)) {
            return new byte[0];
        }
        String[] tokens = pem.split(beginDelimiter);
        tokens = tokens[1].split(endDelimiter);
        return Base64.getMimeDecoder().decode(tokens[0]);
    }

    /**
     * Extracts the private key from the given {@code .pem} file's contents.
     *
     * @param pem the contents of the {@code .pem} file.
     * @return the private key, or empty array if the private key was not found.
     * @throws IllegalArgumentException if the private key data is not properly {@code base64}
     *     encoded.
     */
    public static byte[] extractPrivateKey(String pem) {
        return parseDerFromPem(pem, BEGIN_PRIVATE_KEY_TOKEN, END_PRIVATE_KEY_TOKEN);
    }

    /**
     * Tells whether or not the given {@code .pem} file contents contain a section with the given
     * begin and end tokens.
     *
     * @param contents the {@code .pem} file contents to check if contains the section.
     * @param beginToken the begin token of the section.
     * @param endToken the end token of the section.
     * @return {@code true} if the section was found, {@code false} otherwise.
     */
    private static boolean containsSection(String contents, String beginToken, String endToken) {
        int idxToken;
        if ((idxToken = contents.indexOf(beginToken)) == -1
                || contents.indexOf(endToken) < idxToken) {
            return false;
        }
        return true;
    }

    /**
     * Converts pem data into a {@code KeyStore}.
     *
     * @param certBytes the certificate.
     * @param keyBytes the private key.
     * @return the {@code KeyStore}.
     * @throws IOException if an error occurred while loading the {@code KeyStore}.
     * @throws GeneralSecurityException if an error occurred while manipulating the certificate or
     *     its keys.
     */
    public static KeyStore pemToKeyStore(byte[] certBytes, byte[] keyBytes)
            throws IOException, GeneralSecurityException {
        X509Certificate certificate = generateCertificateFromDer(certBytes);
        RSAPrivateKey privateKey = generatePrivateKeyFromDer(keyBytes);
        return createKeyStore(privateKey, certificate);
    }

    private static RSAPrivateKey generatePrivateKeyFromDer(byte[] keyBytes)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) factory.generatePrivate(spec);
    }

    private static X509Certificate generateCertificateFromDer(byte[] certBytes)
            throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    /**
     * Converts the certificate contained in the given {@code KeyStore} into a pem.
     *
     * @param keyStore the {@code KeyStore}.
     * @return the string containing the certificate as pem.
     */
    public static String keyStoreToCertificatePem(KeyStore keyStore) {
        StringWriter writer = new StringWriter();
        writeCertAsPem(keyStore, writer);
        return writer.toString();
    }

    private static void writeCertAsPem(KeyStore keyStore, Writer writer) {
        if (keyStore == null) {
            return;
        }

        Certificate cert = getCertificate(keyStore);
        if (cert == null) {
            return;
        }

        try (PemWriter pw = new PemWriter(writer)) {
            pw.writeObject(new JcaMiscPEMGenerator(cert));
            pw.flush();
        } catch (Exception e) {
            LOGGER.error("An error occurred while converting root CA certificate to PEM:", e);
        }
    }

    /**
     * Gets the certificate from the given {@code KeyStore}.
     *
     * @param keyStore the {@code KeyStore} with the certificate.
     * @return the certificate or {@code null} if not able to get it.
     */
    public static X509Certificate getCertificate(KeyStore keyStore) {
        if (keyStore == null) {
            return null;
        }

        try {
            return (X509Certificate) keyStore.getCertificate(ZAPROXY_JKS_ALIAS);
        } catch (KeyStoreException e) {
            LOGGER.error("An error occurred while getting the certificate from the KeyStore:", e);
        }
        return null;
    }

    /**
     * Writes the certificate contained in the given {@code KeyStore} into a file in pem format.
     *
     * @param keyStore the {@code KeyStore}.
     * @param file the file to write to.
     */
    public static void keyStoreToCertificatePem(KeyStore keyStore, Path file) {
        try (Writer writer = Files.newBufferedWriter(file, StandardCharsets.US_ASCII)) {
            writeCertAsPem(keyStore, writer);
        } catch (Exception e) {
            LOGGER.error("An error occurred while creating the writer:", e);
        }
    }

    /**
     * Writes the certificate and private key contained in the given {@code KeyStore} into a file in
     * pem format.
     *
     * @param keyStore the {@code KeyStore}.
     * @param file the file to write to.
     */
    public static void keyStoreToCertificateAndPrivateKeyPem(KeyStore keyStore, Path file) {
        keyStoreToCertificatePem(keyStore, file);

        try (Writer writer =
                        Files.newBufferedWriter(
                                file, StandardCharsets.US_ASCII, StandardOpenOption.APPEND);
                PemWriter pw = new PemWriter(writer)) {
            byte[] privateKeyEncoded = getPrivateKey(keyStore).getEncoded();
            pw.writeObject(new MiscPEMGenerator(new PemObject("PRIVATE KEY", privateKeyEncoded)));
            pw.flush();
        } catch (Exception e) {
            LOGGER.error("An error occurred while writing the private key:", e);
        }
    }

    /**
     * Gets the private key from the given {@code KeyStore}.
     *
     * @param keyStore the {@code KeyStore} with the key.
     * @return the private key or {@code null} if not able to get it.
     */
    public static PrivateKey getPrivateKey(KeyStore keyStore) {
        if (keyStore == null) {
            return null;
        }

        try {
            return (PrivateKey) keyStore.getKey(ZAPROXY_JKS_ALIAS, PASSPHRASE);
        } catch (Exception e) {
            LOGGER.error("An error occurred while creating the writer:", e);
        }
        return null;
    }
}
