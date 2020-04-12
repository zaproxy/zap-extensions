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
package org.zaproxy.zap.extension.jwt.attacks;

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.NULL_BYTE_CHARACTER;

import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.jwt.JWTHolder;
import org.zaproxy.zap.extension.jwt.utils.JWTConstants;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/**
 * This class contains attacks related to manipulation of JWT payloads.
 *
 * @author preetkaran20@gmail.com KSASAN
 * @since TODO add version
 */
public class PayloadAttack implements JWTAttack {

    private static final Logger LOGGER = Logger.getLogger(PayloadAttack.class);
    private static final String MESSAGE_PREFIX = "jwt.scanner.server.vulnerability.payloadAttack.";
    private ServerSideAttack serverSideAttack;

    private boolean executAttackAndRaiseAlert(
            String newJWTToken, VulnerabilityType vulnerabilityType) {
        boolean result = verifyJWTToken(newJWTToken, serverSideAttack);
        if (result) {
            raiseAlert(
                    MESSAGE_PREFIX,
                    vulnerabilityType,
                    Alert.RISK_HIGH,
                    Alert.CONFIDENCE_HIGH,
                    newJWTToken,
                    this.serverSideAttack);
        }
        return result;
    }

    /**
     * Adds Null Byte and ZAP Eye catcher after the payload to check if JWT signature is still
     * valid. if Signature is still valid then JWT validator is vulnerable to Null Byte Injection.
     */
    private boolean executeNullByteAttack() {
        String nullBytePayload = NULL_BYTE_CHARACTER + Constant.getEyeCatcher();
        JWTHolder clonedJWTToken = new JWTHolder(this.serverSideAttack.getJwtHolder());
        try {
            if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
                return false;
            }
            // Adding null byte to payload encoded with base64 encoding
            String base64EncodedTokenWithoutSignature =
                    clonedJWTToken.getBase64EncodedTokenWithoutSignature();
            if (executAttackAndRaiseAlert(
                    base64EncodedTokenWithoutSignature
                            + nullBytePayload
                            + JWTConstants.JWT_TOKEN_PERIOD_CHARACTER
                            + JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(
                                    clonedJWTToken.getSignature()),
                    VulnerabilityType.NULL_BYTE)) {
                return true;
            }

            // Here we are adding null byte to payload which is not encoded with base64
            // encoding.
            JSONObject payloadJsonObject = new JSONObject(clonedJWTToken.getPayload());
            for (String key : payloadJsonObject.keySet()) {
                if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
                    return false;
                }
                Object originalKeyValue = payloadJsonObject.get(key);
                if (originalKeyValue instanceof String) {
                    payloadJsonObject.put(key, originalKeyValue.toString() + nullBytePayload);
                    clonedJWTToken.setPayload(payloadJsonObject.toString());
                    if (executAttackAndRaiseAlert(
                            clonedJWTToken.getBase64EncodedToken(), VulnerabilityType.NULL_BYTE)) {
                        return true;
                    }
                    payloadJsonObject.put(key, originalKeyValue);
                }
            }
        } catch (JSONException e) {
            // Payload can be json or any other format as per specification.
            LOGGER.error("Payload is not a valid JSON Object", e);
        }
        return false;
    }

    @Override
    public boolean executeAttack(ServerSideAttack serverSideAttack) {
        this.serverSideAttack = serverSideAttack;
        return executeNullByteAttack();
    }
}
