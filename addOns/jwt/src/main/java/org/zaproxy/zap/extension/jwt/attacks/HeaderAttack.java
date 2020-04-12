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

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.HEADER_FORMAT_VARIANTS;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.NONE_ALGORITHM_VARIANTS;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.jwt.JWTHolder;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/**
 * This class contains attacks related to manipulation of JWT header fields.
 *
 * @author preetkaran20@gmail.com KSASAN
 * @since TODO add version
 */
public class HeaderAttack implements JWTAttack {

    private static final String MESSAGE_PREFIX = "jwt.scanner.server.vulnerability.headerAttack.";

    private ServerSideAttack serverSideAttack;

    private boolean executeAttackAndRaiseAlert(
            JWTHolder clonedJWTHolder, VulnerabilityType vulnerabilityType) {
        if (verifyJWTToken(clonedJWTHolder.getBase64EncodedToken(), serverSideAttack)) {
            raiseAlert(
                    MESSAGE_PREFIX,
                    vulnerabilityType,
                    Alert.RISK_HIGH,
                    Alert.CONFIDENCE_HIGH,
                    clonedJWTHolder.getBase64EncodedToken(),
                    serverSideAttack);
            return true;
        }
        return false;
    }

    /**
     * There are multiple variants of NONE algorithm attack, this method executes all those attacks
     * returning {@code true} if successful otherwise {@code false}.
     *
     * @param jwtHolder parsed parameter value (JWT Token) present in httpMessage.
     * @return {@code true} if None Algorithm Attack is successful else {@code false}
     */
    private boolean executeNoneAlgorithmVariantAttacks(JWTHolder jwtHolder) {
        JWTHolder clonedJWTHolder = new JWTHolder(jwtHolder);
        for (String noneVariant : NONE_ALGORITHM_VARIANTS) {
            for (String headerVariant : this.manipulatingHeaders(noneVariant)) {
                if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
                    return false;
                }
                clonedJWTHolder.setHeader(headerVariant);
                clonedJWTHolder.setSignature(JWTUtils.getBytes(""));
                if (this.executeAttackAndRaiseAlert(
                        clonedJWTHolder, VulnerabilityType.NONE_ALGORITHM)) {
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
    public boolean executeAttack(ServerSideAttack serverSideAttack) {
        this.serverSideAttack = serverSideAttack;
        JWTHolder jwtHolder = this.serverSideAttack.getJwtHolder();
        return executeNoneAlgorithmVariantAttacks(jwtHolder);
    }
}
