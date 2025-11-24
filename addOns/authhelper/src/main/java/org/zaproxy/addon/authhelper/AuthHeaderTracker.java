/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.users.User;

/**
 * Records any authorization headers on a per host basis. If any authenticated requests are made
 * then this class will update them with the last known header.
 */
public class AuthHeaderTracker implements HttpSenderListener {

    private static final Logger LOGGER = LogManager.getLogger(AuthHeaderTracker.class);

    private Map<String, Map<String, String>> hostHeaderToken =
            Collections.synchronizedMap(new HashMap<>());

    @Override
    public int getListenerOrder() {
        return 0;
    }

    private String trim(String str) {
        if (str.length() > 40) {
            return str.substring(0, 40) + "...";
        }
        return str;
    }

    private boolean isAuthInitiator(int initiator) {
        return initiator == HttpSender.AUTHENTICATION_HELPER_INITIATOR
                || initiator == HttpSender.AUTHENTICATION_INITIATOR
                || initiator == HttpSender.PROXY_INITIATOR;
    }

    private static boolean isTrackedHeader(String header) {
        return Strings.CI.contains(header, "auth")
                || Strings.CI.contains(header, "csrf")
                || (!"sec-websocket-key".equalsIgnoreCase(header)
                        && Strings.CI.contains(header, "key"))
                || Strings.CI.contains(header, "x-gwt-");
    }

    @Override
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender sender) {
        if (HttpRequestHeader.OPTIONS.equals(msg.getRequestHeader().getMethod())) {
            // Always ignore OPTIONS reqs - they are not expected to have an auth header
            return;
        }

        try {
            String host = SessionStructure.getHostName(msg);
            Map<String, String> latestTokens =
                    hostHeaderToken.computeIfAbsent(
                            host, h -> Collections.synchronizedMap(new HashMap<String, String>()));

            if (isAuthInitiator(initiator)) {
                // Track any auth tokens
                msg.getRequestHeader()
                        .getHeaders()
                        .forEach(
                                hhf -> {
                                    if (isTrackedHeader(hhf.getName())) {
                                        String headerLc = hhf.getName().toLowerCase(Locale.ROOT);
                                        String val1 = latestTokens.get(headerLc);
                                        if (val1 == null) {
                                            latestTokens.put(headerLc, hhf.getValue());
                                            LOGGER.debug(
                                                    "New header for domain {} : {} : {}",
                                                    host,
                                                    headerLc,
                                                    trim(hhf.getValue()));
                                        } else if (!val1.equals(hhf.getValue())) {
                                            latestTokens.put(headerLc, hhf.getValue());
                                            LOGGER.debug(
                                                    "Update header for domain {} : {} : {}",
                                                    host,
                                                    headerLc,
                                                    trim(hhf.getValue()));
                                        }
                                    }
                                });
            } else if (isHeaderAuth(msg.getRequestingUser())) {
                // Always update the tokens for the other senders (apart from the modern spiders,
                // which handle auth themselves)
                latestTokens
                        .entrySet()
                        .forEach(
                                entry ->
                                        msg.getRequestHeader()
                                                .setHeader(entry.getKey(), entry.getValue()));
            }
        } catch (URIException e) {
            LOGGER.debug(e.getMessage(), e);
        }
    }

    private boolean isHeaderAuth(User user) {
        return user != null
                && user.getContext().getSessionManagementMethod()
                        instanceof
                        HeaderBasedSessionManagementMethodType.HeaderBasedSessionManagementMethod;
    }

    @Override
    public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender sender) {
        // Do nothing
    }

    public void clear() {
        hostHeaderToken.clear();
    }

    /* Just for testing */
    protected int getHostCount() {
        return hostHeaderToken.size();
    }

    /* Just for testing */
    protected String getTokenForHost(String host, String header) {
        Map<String, String> latestTokens = hostHeaderToken.get(host);
        if (latestTokens == null) {
            return null;
        }
        return latestTokens.get(header.toLowerCase(Locale.ROOT));
    }
}
