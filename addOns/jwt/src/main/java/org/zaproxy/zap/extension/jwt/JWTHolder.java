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
package org.zaproxy.zap.extension.jwt;

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_ALGORITHM_KEY_HEADER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_TOKEN_PERIOD_CHARACTER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_TOKEN_PERIOD_CHARACTER_REGEX;

import java.util.Arrays;
import java.util.Base64;
import org.json.JSONObject;
import org.zaproxy.zap.extension.jwt.exception.JWTException;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;

/**
 * JWT token is parsed and broken into Header, Payload, and Signature.<br>
 * This class is created for easier computations and manipulation of JWT Token.<br>
 * JWT Holder fields are not encoded in base64 encoding.
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class JWTHolder {

    private String header;
    private String payload;
    private byte[] signature;

    private JWTHolder() {}

    public JWTHolder(JWTHolder jwtHolder) {
        this.header = jwtHolder.getHeader();
        this.payload = jwtHolder.getPayload();
        this.signature = jwtHolder.getSignature();
    }

    /** @return Header without base64 encoding */
    public String getHeader() {
        return header;
    }

    /** @param header without base64 encoding */
    public void setHeader(String header) {
        this.header = header;
    }

    /** @return Payload without base64 encoding */
    public String getPayload() {
        return payload;
    }

    /** @param payload without base64 encoding */
    public void setPayload(String payload) {
        this.payload = payload;
    }

    /** @return Signature without base64 encoding */
    public byte[] getSignature() {
        return signature;
    }

    /** @param signature without base64 encoding */
    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    /** @return algorithm value from Header */
    public String getAlgorithm() {
        JSONObject headerJSONObject = new JSONObject(this.getHeader());
        String algoType = headerJSONObject.getString(JWT_ALGORITHM_KEY_HEADER);
        return algoType;
    }

    /**
     * We are using <a href="https://en.wikipedia.org/wiki/Base64#URL_applications">Base64 URL Safe
     * encoding</a>. because of JWT specifications <br>
     * Also we are removing the padding as per <a
     * href="https://www.rfc-editor.org/rfc/rfc7515.txt">RFC 7515</a> padding is not there in JWT.
     *
     * @return base64 url encoded JWT token
     */
    public String getBase64EncodedToken() {
        String base64EncodedHeader = JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(header);
        String base64EncodedPayload = JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(payload);
        String base64EncodedSignature =
                JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(signature);
        return base64EncodedHeader
                + JWT_TOKEN_PERIOD_CHARACTER
                + base64EncodedPayload
                + JWT_TOKEN_PERIOD_CHARACTER
                + base64EncodedSignature;
    }

    /** @return token to be Signed i.e. base64EncodedHeader.base64EncodedPayload */
    public String getBase64EncodedTokenWithoutSignature() {
        String base64EncodedHeader = JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(header);
        String base64EncodedPayload = JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(payload);
        return base64EncodedHeader + JWT_TOKEN_PERIOD_CHARACTER + base64EncodedPayload;
    }

    /**
     * Parses JWT token and creates JWTHolder instance. we are using <a
     * href="https://en.wikipedia.org/wiki/Base64#URL_applications">Base64 URL Safe encoding</a> as
     * per JWT specifications.<br>
     *
     * @param jwtToken base64 encoded JSON Web Token.
     * @return JWTHolder parsed JWT token.
     * @throws JWTException if provided jwtToken is not a valid JSON Web Token.
     */
    public static JWTHolder parseJWTToken(String jwtToken) throws JWTException {
        if (!JWTUtils.isTokenValid(jwtToken)) {
            throw new JWTException("JWT token:" + jwtToken + " is not valid");
        }
        JWTHolder jwtHolder = new JWTHolder();
        String[] tokens = jwtToken.split(JWT_TOKEN_PERIOD_CHARACTER_REGEX, -1);
        jwtHolder.setHeader(
                JWTUtils.getString(Base64.getUrlDecoder().decode(JWTUtils.getBytes(tokens[0]))));
        jwtHolder.setPayload(
                JWTUtils.getString(Base64.getUrlDecoder().decode(JWTUtils.getBytes(tokens[1]))));
        jwtHolder.setSignature(Base64.getUrlDecoder().decode(JWTUtils.getBytes(tokens[2])));

        return jwtHolder;
    }

    @Override
    public String toString() {
        return "JWTHolder [header="
                + header
                + ", payload="
                + payload
                + ", signature="
                + Arrays.toString(signature)
                + "]";
    }
}
