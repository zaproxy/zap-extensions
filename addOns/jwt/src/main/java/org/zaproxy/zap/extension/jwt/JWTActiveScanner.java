/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.jwt;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.jwt.attacks.BruteforceAttack;
import org.zaproxy.zap.extension.jwt.attacks.ClientSideAttack;
import org.zaproxy.zap.extension.jwt.attacks.ServerSideAttack;
import org.zaproxy.zap.extension.jwt.exception.JWTException;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
import org.zaproxy.zap.model.TechSet;

/**
 * JWT Scanner is used to find the vulnerabilities in JWT implementations. <br>
 * Resources containing more information about vulnerabilities in implementations are: <br>
 *
 * <ol>
 *   <li><a href="https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-06" >JSON Web Token Best
 *       Current Practices(ieft document)</a>
 *   <li><a
 *       href="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html">
 *       OWASP cheatsheet for vulnerabilities in JWT implementation </a>
 *   <li><a href="https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries">For
 *       server side vulnerabilities in JWT implementations</a>
 *   <li><a href="https://github.com/ticarpi/jwt_tool/blob/master/jwt_tool.py">JWT vulnerability
 *       finding tool</a>
 *   <li><a href="https://github.com/andresriancho/jwt-fuzzer">JWT header/payload field fuzzer</a>
 * </ol>
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class JWTActiveScanner extends AbstractAppParamPlugin {

    private static final int PLUGIN_ID = 1001;
    private static final String NAME = JWTI18n.getMessage("ascanrules.jwt.name");
    private static final String DESCRIPTION = JWTI18n.getMessage("ascanrules.jwt.description");
    private static final Logger LOGGER = Logger.getLogger(JWTActiveScanner.class);
    private AtomicInteger maxRequestCount = new AtomicInteger(0);

    public JWTActiveScanner() {}

    @Override
    public void init() {
        switch (this.getAttackStrength()) {
            case LOW:
                maxRequestCount = new AtomicInteger(120);
                break;
            case MEDIUM:
                maxRequestCount = new AtomicInteger(250);
                break;
            case HIGH:
                maxRequestCount = new AtomicInteger(500);
                break;
            case INSANE:
                maxRequestCount = new AtomicInteger(10000000);
                break;
            default:
                break;
        }
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        String newValue = value.trim();
        newValue = JWTUtils.extractingJWTFromParamValue(newValue);

        if (!JWTUtils.isTokenValid(newValue)) {
            LOGGER.info("Token: " + newValue + " is not a valid JWT token.");
            return;
        }
        // Sending request to save actual response and then compare it with new response
        try {
            sendAndReceive(msg);
        } catch (IOException e) {
            LOGGER.error(e);
            return;
        }

        JWTTokenBean jwtTokenBean;
        try {
            jwtTokenBean = JWTTokenBean.parseJWTToken(newValue);
        } catch (JWTException e) {
            LOGGER.error("Unable to parse JWT Token", e);
            return;
        }

        if (!JWTConfiguration.getInstance().isIgnoreClientConfigurationScan()) {
            if (performAttackClientSideConfigurations(msg, param, jwtTokenBean, value)) {
                return;
            }
            this.decreaseRequestCount();
        }
        performAttackServerSideConfigurations(msg, param, jwtTokenBean, value);
    }

    public boolean isStop() {
        return super.isStop() || (this.maxRequestCount.get() <= 0);
    }

    public void decreaseRequestCount() {
        this.maxRequestCount.decrementAndGet();
    }

    /**
     * performs attack to find if client side configuration for JWT token is proper.
     *
     * @param msg
     * @param param
     * @param jwtTokenBean
     * @return {@code true} if the vulnerability is found, {@code false} otherwise.
     */
    private boolean performAttackClientSideConfigurations(
            HttpMessage msg, String param, JWTTokenBean jwtTokenBean, String value) {
        return new ClientSideAttack(this, param, msg).execute();
    }

    /**
     * performs attack to find JWT implementation weaknesses like weak key usage or other types of
     * attacks.
     *
     * @param msg
     * @param param
     * @param jwtTokenBean
     * @return {@code true} if the vulnerability is found, {@code false} otherwise.
     */
    private boolean performAttackServerSideConfigurations(
            HttpMessage msg, String param, JWTTokenBean jwtTokenBean, String value) {

        // TODO there are scenarios where base64 encoded secrete is used in JWT. more
        // information in
        // below link
        // https://stackoverflow.com/questions/58044813/how-to-create-a-jwt-in-java-with-the-secret-base64-encoded
        boolean result = new ServerSideAttack(jwtTokenBean, this, param, msg, value).execute();
        if (!result) {
            result = new BruteforceAttack(jwtTokenBean, this, param, msg).execute();
        }
        return result;
    }

    /**
     * Waits some time to check if token is expired and then execute the attack. TODO need to
     * implement it.
     *
     * @param jwtTokenBean
     * @param msg
     * @param param
     * @return
     */
    private boolean checkExpiredTokenAttack(
            JWTTokenBean jwtTokenBean, HttpMessage msg, String param) {
        return false;
    }

    public void bingo(
            int risk,
            int confidence,
            String name,
            String description,
            String uri,
            String param,
            String attack,
            String otherInfo,
            String solution,
            HttpMessage msg) {
        super.bingo(
                risk, confidence, name, description, uri, param, attack, otherInfo, solution, msg);
    }

    /**
     * @param msg
     * @param param
     * @param jwtToken
     * @return {@code true} if the vulnerability is found, {@code false} otherwise.
     */
    public boolean sendFuzzedMsgAndCheckIfAttackSuccessful(
            HttpMessage msg, String param, String jwtToken, String value) {
        HttpMessage newMsg = this.getNewMsg();
        this.setParameter(newMsg, param, JWTUtils.addingJWTToParamValue(value, jwtToken));
        try {
            this.sendAndReceive(newMsg, false);
            if (newMsg.getResponseHeader().getStatusCode()
                            == msg.getResponseHeader().getStatusCode()
                    && newMsg.getResponseBody().equals(msg.getResponseBody())) {
                return true;
            }
        } catch (IOException e) {
            LOGGER.error("Following exception occurred while sending fuzzed jwt message", e);
        }
        return false;
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    @Override
    public String getSolution() {
        return "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html";
    }

    @Override
    public String getReference() {
        return "https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-06";
    }

    @Override
    public TechSet getTechSet() {
        TechSet techSet = super.getTechSet();
        if (techSet != null) {
            return techSet;
        }
        return TechSet.AllTech;
    }

    @Override
    public int getCategory() {
        return 0;
    }
}
