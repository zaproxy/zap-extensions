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

import org.zaproxy.zap.extension.jwt.JWTI18n;
import org.zaproxy.zap.extension.jwt.attacks.ServerSideAttack;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/**
 * JWTFuzzer is the common interface for all the jwt fuzzers.
 *
 * @author preetkaran20@gmail.com KSASAN
 * @since TODO add version
 */
public interface JWTFuzzer {

    /**
     * Executes the attack and returns {@code true} if successful otherwise false.
     *
     * @param fuzzedJWTToken
     * @param serverSideAttack
     * @return
     */
    default boolean executeAttack(String fuzzedJWTToken, ServerSideAttack serverSideAttack) {
        serverSideAttack.getJwtActiveScanner().decreaseRequestCount();
        return serverSideAttack
                .getJwtActiveScanner()
                .sendFuzzedMsgAndCheckIfAttackSuccessful(
                        serverSideAttack.getMsg(),
                        serverSideAttack.getParam(),
                        fuzzedJWTToken,
                        serverSideAttack.getParamValue());
    }

    /**
     * Raises Alert for all the JWT fuzzers.
     *
     * @param messagePrefix
     * @param vulnerabilityType
     * @param alertLevel
     * @param confidenceLevel
     * @param serverSideAttack
     */
    default void raiseAlert(
            String messagePrefix,
            VulnerabilityType vulnerabilityType,
            int alertLevel,
            int confidenceLevel,
            String jwtToken,
            ServerSideAttack serverSideAttack) {
        serverSideAttack
                .getJwtActiveScanner()
                .bingo(
                        alertLevel,
                        confidenceLevel,
                        JWTI18n.getMessage(
                                messagePrefix + vulnerabilityType.getMessageKey() + ".name"),
                        JWTI18n.getMessage(
                                messagePrefix + vulnerabilityType.getMessageKey() + ".desc"),
                        serverSideAttack.getMsg().getRequestHeader().getURI().toString(),
                        serverSideAttack.getParam(),
                        jwtToken,
                        JWTI18n.getMessage(
                                messagePrefix + vulnerabilityType.getMessageKey() + ".refs"),
                        JWTI18n.getMessage(
                                messagePrefix + vulnerabilityType.getMessageKey() + ".soln"),
                        serverSideAttack.getMsg());
    }
    /**
     * Manipulates the JWT token, executes them and also raise alert if successful
     *
     * @param serverSideAttack
     * @return true if attack is successful.
     */
    boolean fuzzJWTTokens(ServerSideAttack serverSideAttack);
}
