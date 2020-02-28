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

import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.jwt.attacks.ServerSideAttack;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/**
 * This class contains attacks related to manipulation of more than one component of JWT token.
 *
 * @author preetkaran20@gmail.com KSASAN
 * @since TODO add version
 */
public class MiscFuzzer implements JWTFuzzer {

    private static final String MESSAGE_PREFIX = "jwt.scanner.server.vulnerability.miscFuzzer.";

    private ServerSideAttack serverSideAttack;

    private boolean executeAttack(String fuzzedJWTToken) {
        if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
            return false;
        }
        boolean result = executeAttack(fuzzedJWTToken, serverSideAttack);
        if (result) {
            raiseAlert(
                    MESSAGE_PREFIX,
                    VulnerabilityType.EMPTY_TOKENS,
                    Alert.RISK_HIGH,
                    Alert.CONFIDENCE_HIGH,
                    fuzzedJWTToken,
                    this.serverSideAttack);
        }
        return result;
    }

    /**
     *
     *
     * <ol>
     *   <li>Adds empty header/payload/signature
     *   <li>Adds multiple dots in tokens
     *       <ol>
     */
    private boolean executeEmptyPayloads() {
        return executeAttack("...") || executeAttack(".....");
    }

    @Override
    public boolean fuzzJWTTokens(ServerSideAttack serverSideAttack) {
        this.serverSideAttack = serverSideAttack;
        return executeEmptyPayloads();
    }
}
