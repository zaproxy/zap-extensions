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

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.HEADER_FORMAT_VARIANTS;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWK_SET_URL_HEADER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.KEY_ID_HEADER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.NONE_ALGORITHM_VARIANTS;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler.FileStringPayloadGeneratorUI;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.attacks.GenericAsyncTaskExecutor;
import org.zaproxy.zap.extension.jwt.attacks.ServerSideAttack;
import org.zaproxy.zap.extension.jwt.exception.JWTException;
import org.zaproxy.zap.extension.jwt.ui.CustomFieldFuzzer;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/**
 * This class contains attacks related to manipulation of header fields of JWT token.
 *
 * @author preetkaran20@gmail.com KSASAN
 * @since TODO add version
 */
public class HeaderFuzzer implements JWTFuzzer {

    private static final Logger LOGGER = Logger.getLogger(HeaderFuzzer.class);

    private static final String MESSAGE_PREFIX = "jwt.scanner.server.vulnerability.headerFuzzer.";

    private ServerSideAttack serverSideAttack;

    private boolean executeAttackAndRaiseAlert(
            JWTTokenBean clonJWTTokenBean, VulnerabilityType vulnerabilityType) {
        if (executeAttack(clonJWTTokenBean.getBase64EncodedToken(), serverSideAttack)) {
            raiseAlert(
                    MESSAGE_PREFIX,
                    vulnerabilityType,
                    Alert.RISK_HIGH,
                    Alert.CONFIDENCE_HIGH,
                    clonJWTTokenBean.getBase64EncodedToken(),
                    serverSideAttack);
            return true;
        }
        return false;
    }

    private boolean handleCustomFuzzers(JWTTokenBean jwtTokenBean) {
        JWTTokenBean clonedJWTokenBean = new JWTTokenBean(jwtTokenBean);
        JSONObject headerJSONObject = new JSONObject(clonedJWTokenBean.getHeader());
        List<CustomFieldFuzzer> customFieldFuzzers =
                JWTConfiguration.getInstance().getCustomFieldFuzzers();
        for (CustomFieldFuzzer customFieldFuzzer : customFieldFuzzers) {
            if (customFieldFuzzer.isHeaderField()) {
                if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
                    return false;
                }
                String jwtHeaderField = customFieldFuzzer.getFieldName();
                FileStringPayloadGeneratorUI fileStringPayloadGeneratorUI =
                        customFieldFuzzer.getFileStringPayloadGeneratorUI();
                if (fileStringPayloadGeneratorUI == null) {
                    continue;
                }
                Predicate<DefaultPayload> predicate =
                        (fieldValue) -> {
                            if (headerJSONObject.has(jwtHeaderField)) {
                                headerJSONObject.put(jwtHeaderField, fieldValue);
                                clonedJWTokenBean.setHeader(headerJSONObject.toString());
                                if (customFieldFuzzer.isSignatureRequired()) {
                                    try {
                                        JWTUtils.handleSigningOfTokenCustomFieldFuzzer(
                                                customFieldFuzzer, clonedJWTokenBean);
                                        return executeAttackAndRaiseAlert(
                                                clonedJWTokenBean,
                                                VulnerabilityType.CUSTOM_PAYLOAD);
                                    } catch (JWTException e) {
                                        LOGGER.error(
                                                "Failed while signing the clonedJWTTokenBean:", e);
                                    }
                                    return false;
                                } else {
                                    return executeAttackAndRaiseAlert(
                                            clonedJWTokenBean, VulnerabilityType.CUSTOM_PAYLOAD);
                                }
                            } else {
                                return false;
                            }
                        };

                GenericAsyncTaskExecutor<DefaultPayload> genericTaskExecutor =
                        new GenericAsyncTaskExecutor<DefaultPayload>(
                                predicate,
                                fileStringPayloadGeneratorUI.getPayloadGenerator().iterator(),
                                this.serverSideAttack.getJwtActiveScanner());
                if (genericTaskExecutor.execute()) {
                    return true;
                }
            }
        }
        return false;
    }

    // TODO adding JKU etc payloads
    // (https://github.com/andresriancho/jwt-fuzzer/blob/master/jwtfuzzer/fuzzing_functions/header_jku.py)
    // If JKU holds read if there are any vulnerabilities exists.

    /**
     * Kid field is used to identify Algorithm and Key for JWT. Kid field protects against the
     * {@code SignatureFuzzer#getAlgoKeyConfusionFuzzedToken} payload.
     *
     * <p>this fuzzed tokens are used to check vulnerabilities in kid implementation. <a
     * href=https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-06#section-3.10>More
     * information</a>
     *
     * @param jwtTokenBean
     */
    private boolean populateKidOrJkuHeaderManipulatedFuzzedToken(JWTTokenBean jwtTokenBean) {
        JWTTokenBean clonedJWTokenBean = new JWTTokenBean(jwtTokenBean);
        JSONObject headerJSONObject = new JSONObject(clonedJWTokenBean.getHeader());
        if (headerJSONObject.has(KEY_ID_HEADER)) {
            // Kid Field is there.
            // Kid fields if using LDAP or SQLInjection can cause issues.
            // Add payload fuzzers for LDAP and SQL Injection.
        } else if (headerJSONObject.has(JWK_SET_URL_HEADER)) {
            // Try finding if SSRF is there or not.
            // Can use timebased attack for knowing if calling malicious site is visited
        }
        return false;
    }

    /**
     * There are various variants of NONE algorithm attack and this method executes all those
     * attacks and returns true if successful otherwise false.
     *
     * @param jwtTokenBean
     * @return
     */
    private boolean executeNoneAlgorithmVariantAttacks(JWTTokenBean jwtTokenBean) {
        JWTTokenBean clonedJWTokenBean = new JWTTokenBean(jwtTokenBean);
        for (String noneVariant : NONE_ALGORITHM_VARIANTS) {
            for (String headerVariant : this.manipulatingHeaders(noneVariant)) {
                if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
                    return false;
                }
                clonedJWTokenBean.setHeader(headerVariant);
                clonedJWTokenBean.setSignature(JWTUtils.getBytes(""));
                if (this.executeAttackAndRaiseAlert(
                        clonedJWTokenBean, VulnerabilityType.NONE_ALGORITHM)) {
                    return true;
                }
            }
        }
        return false;
    }

    private List<String> manipulatingHeaders(String algo) {
        List<String> fuzzedHeaders = new ArrayList<>();
        for (String headerVariant : HEADER_FORMAT_VARIANTS) {
            String fuzzedHeader = String.format(headerVariant, algo);
            fuzzedHeaders.add(fuzzedHeader);
        }
        return fuzzedHeaders;
    }

    @Override
    public boolean fuzzJWTTokens(ServerSideAttack serverSideAttack) {
        this.serverSideAttack = serverSideAttack;
        JWTTokenBean jwtTokenBean = this.serverSideAttack.getJwtTokenBean();
        return executeNoneAlgorithmVariantAttacks(jwtTokenBean)
                || this.handleCustomFuzzers(jwtTokenBean)
                || populateKidOrJkuHeaderManipulatedFuzzedToken(jwtTokenBean);
    }
}
