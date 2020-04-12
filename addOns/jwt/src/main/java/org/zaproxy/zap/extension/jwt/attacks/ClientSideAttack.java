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
package org.zaproxy.zap.extension.jwt.attacks;

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.COOKIE_PREFIX_HOST;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.COOKIE_PREFIX_SECURE;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.HTTP_ONLY_COOKIE_ATTRIBUTE;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.SAME_SITE_ATTRIBUTE;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.SAME_SITE_NONE_MODE;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.SECURE_COOKIE_ATTRIBUTE;

import java.util.List;
import java.util.TreeSet;
import org.apache.commons.collections.iterators.IteratorChain;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.jwt.JWTActiveScanner;
import org.zaproxy.zap.extension.jwt.JWTI18n;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;
import org.zaproxy.zap.sharedutils.CookieUtils;

/**
 * This class is used to find vulnerability in Client side implementation of JWT token.
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class ClientSideAttack {

    private JWTActiveScanner jwtActiveScanner;
    private String param;
    private HttpMessage msg;

    private static final String MESSAGE_PREFIX = "jwt.scanner.client.vulnerability.";

    private void raiseAlert(
            VulnerabilityType vulnerabilityType,
            int risk,
            int confidence,
            String param,
            HttpMessage msg) {
        this.jwtActiveScanner.raiseAlert(
                risk,
                confidence,
                JWTI18n.getMessage(MESSAGE_PREFIX + vulnerabilityType.getMessageKey() + ".name"),
                JWTI18n.getMessage(MESSAGE_PREFIX + vulnerabilityType.getMessageKey() + ".desc"),
                msg.getRequestHeader().getURI().toString(),
                param,
                "",
                JWTI18n.getMessage(MESSAGE_PREFIX + vulnerabilityType.getMessageKey() + ".refs"),
                JWTI18n.getMessage(MESSAGE_PREFIX + vulnerabilityType.getMessageKey() + ".soln"),
                msg);
    }

    /**
     * @param jwtActiveScanner
     * @param param parameter having JWT token
     * @param msg original Http Message
     */
    public ClientSideAttack(JWTActiveScanner jwtActiveScanner, String param, HttpMessage msg) {
        this.jwtActiveScanner = jwtActiveScanner;
        this.param = param;
        this.msg = msg;
    }

    /**
     * @return Iterator for iterating through the {@link HttpHeader#SET_COOKIE} and {@link
     *     HttpHeader#SET_COOKIE2} Header.
     */
    private IteratorChain getCookieIterator() {
        IteratorChain iterator = new IteratorChain();
        List<String> cookies1 = msg.getResponseHeader().getHeaderValues(HttpHeader.SET_COOKIE);

        if (cookies1 != null) {
            iterator.addIterator(cookies1.iterator());
        }

        List<String> cookies2 = msg.getResponseHeader().getHeaderValues(HttpHeader.SET_COOKIE2);

        if (cookies2 != null) {
            iterator.addIterator(cookies2.iterator());
        }
        return iterator;
    }

    public boolean execute() {
        // Check Cookie Values
        boolean paramExists = false;
        IteratorChain setCookieHeaderIterator = getCookieIterator();
        while (setCookieHeaderIterator.hasNext()) {
            String headerValue = (String) setCookieHeaderIterator.next();
            String cookieKey = CookieUtils.getCookieName(headerValue);
            if (cookieKey != null && cookieKey.equals(this.param)) {
                paramExists = true;
                if (!CookieUtils.hasAttribute(headerValue, HTTP_ONLY_COOKIE_ATTRIBUTE)
                        || !CookieUtils.hasAttribute(headerValue, SECURE_COOKIE_ATTRIBUTE)) {
                    VulnerabilityType vulnerabilityType = VulnerabilityType.SECURE_COOKIE;
                    if (!CookieUtils.hasAttribute(headerValue, HTTP_ONLY_COOKIE_ATTRIBUTE)) {
                        vulnerabilityType = VulnerabilityType.HTTPONLY_COOKIE;
                    }
                    this.raiseAlert(
                            vulnerabilityType, Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, param, msg);
                    return true;
                } else if (!CookieUtils.hasAttribute(headerValue, SAME_SITE_ATTRIBUTE)) {
                    this.raiseAlert(
                            VulnerabilityType.SAMESITE_COOKIE,
                            Alert.RISK_MEDIUM,
                            Alert.CONFIDENCE_HIGH,
                            param,
                            msg);
                    return true;
                } else if (CookieUtils.hasAttribute(headerValue, SAME_SITE_ATTRIBUTE)) {
                    if (CookieUtils.getAttributeValue(headerValue, SAME_SITE_ATTRIBUTE)
                            .equalsIgnoreCase(SAME_SITE_NONE_MODE)) {
                        this.raiseAlert(
                                VulnerabilityType.SAMESITE_COOKIE,
                                Alert.RISK_LOW,
                                Alert.CONFIDENCE_LOW,
                                param,
                                msg);
                        return true;
                    }
                } else {
                    if (!param.startsWith(COOKIE_PREFIX_SECURE)
                            || !param.startsWith(COOKIE_PREFIX_HOST)) {
                        this.raiseAlert(
                                VulnerabilityType.COOKIE_PREFIX,
                                Alert.RISK_INFO,
                                Alert.CONFIDENCE_LOW,
                                param,
                                msg);
                        return true;
                    }
                }
                break;
            }
        }
        if (!paramExists) {
            TreeSet<HtmlParameter> queryParams = msg.getUrlParams();
            for (HtmlParameter htmlParameter : queryParams) {
                if (htmlParameter.getName().equals(param)) {
                    this.raiseAlert(
                            VulnerabilityType.URL_PARAM,
                            Alert.RISK_HIGH,
                            Alert.CONFIDENCE_HIGH,
                            param,
                            msg);
                    return true;
                }
            }

            TreeSet<HtmlParameter> formHtmlParameters = msg.getFormParams();
            for (HtmlParameter htmlParameter : formHtmlParameters) {
                if (htmlParameter.getName().equals(param)) {
                    this.raiseAlert(
                            VulnerabilityType.FORM_PARAM,
                            Alert.RISK_INFO,
                            Alert.CONFIDENCE_LOW,
                            param,
                            msg);
                    return true;
                }
            }
        }
        return false;
    }
}
