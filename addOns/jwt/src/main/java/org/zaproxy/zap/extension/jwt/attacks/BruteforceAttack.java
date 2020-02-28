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

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_HMAC_ALGORITHM_IDENTIFIER;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.jwt.JWTActiveScanner;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTI18n;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.exception.JWTException;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/**
 * Executes BruteForce Attack in multiple threads for faster execution. Basic Idea for bruteforce
 * attack is
 *
 * <ol>
 *   <li>Dictionary based attack where user can provide the dictionary of common secrets and then
 *       bruteforcing based on the dictionary.
 *   <li>Common password dictionary provided by ZAP based attack.
 *   <li>Permutation based attack.
 *       <ol>
 *         <li>Get the max length of the secret as an input or will be default length as per the HS
 *             algorithm
 *         <li>Get the characters used as the secret as an input or will be default as [a-zA-Z0-9]
 *         <li>Permute the characters then generate HMAC and then run the attack in multiple
 *             threads.
 *       </ol>
 * </ol>
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class BruteforceAttack {

    private static final String DEFAULT_SECRET_KEY_CHARACTERS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Logger LOGGER = Logger.getLogger(JWTActiveScanner.class);
    private int hmacMaxKeyLength;
    private static final String MESSAGE_PREFIX = "jwt.scanner.server.vulnerability.";

    private JWTTokenBean jwtTokenBean;
    private JWTActiveScanner jwtActiveScanner;
    private HttpMessage msg;
    private String param;
    private boolean isAttackSuccessful = false;
    private List<String> permutedSecretKeys = new ArrayList<String>();

    /**
     * @param jwtTokenBean Parsed JWT Token Bean
     * @param jwtActiveScanner
     * @param msg original Http Message
     * @param param parameter having JWT token
     */
    public BruteforceAttack(
            JWTTokenBean jwtTokenBean,
            JWTActiveScanner jwtActiveScanner,
            String param,
            HttpMessage msg) {
        this.jwtActiveScanner = jwtActiveScanner;
        this.jwtTokenBean = jwtTokenBean;
        this.param = param;
        this.msg = msg;
        this.hmacMaxKeyLength = JWTConfiguration.getInstance().getHmacMaxKeyLength();
    }

    private void raiseAlert(String secretKey) {
        this.jwtActiveScanner.bingo(
                Alert.RISK_HIGH,
                Alert.CONFIDENCE_HIGH,
                JWTI18n.getMessage(
                        MESSAGE_PREFIX + VulnerabilityType.BRUTE_FORCE.getMessageKey() + ".name"),
                JWTI18n.getMessage(
                        MESSAGE_PREFIX + VulnerabilityType.BRUTE_FORCE.getMessageKey() + ".desc"),
                this.msg.getRequestHeader().getURI().toString(),
                this.param,
                secretKey,
                JWTI18n.getMessage(
                        MESSAGE_PREFIX + VulnerabilityType.BRUTE_FORCE.getMessageKey() + ".refs"),
                JWTI18n.getMessage(
                        MESSAGE_PREFIX + VulnerabilityType.BRUTE_FORCE.getMessageKey() + ".soln"),
                this.msg);
    }

    private void generatingHMACSecretKeyAndExecutingAttack(
            StringBuilder secretKey, int index, int keyLength) {
        if (isStop()) {
            LOGGER.info(
                    "Stopping because either attack is successful or user has manually stopped the execution");
            return;
        }
        if (index == keyLength) {
            permutedSecretKeys.add(secretKey.toString());
            if (permutedSecretKeys.size() >= 10) {
                GenericAsyncTaskExecutor<String> genericAsyncTaskExecutor =
                        new GenericAsyncTaskExecutor<String>(
                                getPredicateForVerifyingHMACSecretKey(),
                                permutedSecretKeys.iterator(),
                                this.jwtActiveScanner);
                permutedSecretKeys = new ArrayList<String>();
                isAttackSuccessful = genericAsyncTaskExecutor.execute();
            }
        } else {
            for (int i = 0; i < DEFAULT_SECRET_KEY_CHARACTERS.length(); i++) {
                generatingHMACSecretKeyAndExecutingAttack(
                        secretKey.append(DEFAULT_SECRET_KEY_CHARACTERS.charAt(i)),
                        index + 1,
                        keyLength);
                secretKey.deleteCharAt(index);
            }
        }
    }

    private boolean isStop() {
        if (isAttackSuccessful || this.jwtActiveScanner.isStop()) {
            return true;
        }
        return false;
    }

    private void permutationBasedHMACSecretKeyBruteForce() {
        if (isStop()) {
            LOGGER.info(
                    "Stopping because either attack is successful or user has manually stopped the execution");
            return;
        } else {
            for (int i = 1; i < this.hmacMaxKeyLength; i++) {
                this.generatingHMACSecretKeyAndExecutingAttack(new StringBuilder(), 0, i);
            }
            if (permutedSecretKeys.size() > 0) {
                GenericAsyncTaskExecutor<String> genericAsyncTaskExecutor =
                        new GenericAsyncTaskExecutor<String>(
                                getPredicateForVerifyingHMACSecretKey(),
                                permutedSecretKeys.iterator(),
                                this.jwtActiveScanner);
                permutedSecretKeys = new ArrayList<String>();
                isAttackSuccessful = genericAsyncTaskExecutor.execute();
            }
        }
    }

    private Predicate<String> getPredicateForVerifyingHMACSecretKey() {
        Predicate<String> predicateForVerifyingSecretKey =
                (secretKey) -> {
                    LOGGER.info("Secret Key: " + secretKey);
                    try {
                        String tokenToBeSigned =
                                jwtTokenBean.getBase64EncodedTokenWithoutSignature();
                        String base64EncodedSignature =
                                JWTUtils.getBase64EncodedHMACSignedToken(
                                        JWTUtils.getBytes(tokenToBeSigned),
                                        JWTUtils.getBytes(secretKey),
                                        jwtTokenBean.getAlgorithm());
                        this.jwtActiveScanner.decreaseRequestCount();
                        if (base64EncodedSignature.equals(
                                JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(
                                        this.jwtTokenBean.getSignature()))) {
                            raiseAlert(secretKey);
                            return true;
                        }
                    } catch (JWTException e) {
                        LOGGER.error("Error occurred while generating Signed Token", e);
                    }
                    return false;
                };
        return predicateForVerifyingSecretKey;
    }

    private void fileBasedHMACSecretKeyBruteForce() {
        if (Objects.isNull(JWTConfiguration.getInstance().getPayloadGenerator())) {
            return;
        }
        ResettableAutoCloseableIterator<DefaultPayload> resettableAutoCloseableIterator =
                JWTConfiguration.getInstance().getPayloadGenerator().iterator();
        Predicate<DefaultPayload> wrappedPredicateForVerifyingSecretKey =
                (fieldValue) -> {
                    String secretKey = fieldValue.getValue();
                    return getPredicateForVerifyingHMACSecretKey().test(secretKey);
                };
        GenericAsyncTaskExecutor<DefaultPayload> genericAsyncTaskExecutor =
                new GenericAsyncTaskExecutor<DefaultPayload>(
                        wrappedPredicateForVerifyingSecretKey,
                        resettableAutoCloseableIterator,
                        this.jwtActiveScanner);
        isAttackSuccessful = genericAsyncTaskExecutor.execute();
    }

    public boolean execute() {
        String algoType = this.jwtTokenBean.getAlgorithm();
        if (algoType.startsWith(JWT_HMAC_ALGORITHM_IDENTIFIER)) {
            this.fileBasedHMACSecretKeyBruteForce();
            this.permutationBasedHMACSecretKeyBruteForce();
            if (this.isAttackSuccessful) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
}
