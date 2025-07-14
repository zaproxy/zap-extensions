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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.users.User;

/**
 * Records any authorization headers on a per host basis. If any authenticated requests are made
 * then this class will update them with the last known header.
 */
public class AuthHeaderTracker implements HttpSenderListener {

    private static final Logger LOGGER = LogManager.getLogger(AuthHeaderTracker.class);

    private Map<String, String> hostToToken = new HashMap<>();

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
                || initiator == HttpSender.PROXY_INITIATOR;
    }

    @Override
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender sender) {
        if (HttpRequestHeader.OPTIONS.equals(msg.getRequestHeader().getMethod())) {
            // Always ignore OPTIONS reqs - they are not expected to have an auth header
            return;
        }

        try {
            String host = msg.getRequestHeader().getURI().getHost();
            String latestToken = hostToToken.get(host);

            if (isAuthInitiator(initiator)) {
                // Track any auth tokens
                List<String> authHeaders =
                        msg.getRequestHeader().getHeaderValues(HttpRequestHeader.AUTHORIZATION);
                if (!authHeaders.isEmpty()) {
                    String val1 = authHeaders.get(0);
                    if (latestToken == null) {
                        hostToToken.put(host, val1);
                        LOGGER.debug(
                                "New authorization header for domain {} : {}", host, trim(val1));
                    } else if (!val1.equals(latestToken)) {
                        hostToToken.put(host, val1);
                        LOGGER.debug(
                                "Update authorization header for domain {} : {}", host, trim(val1));
                    }
                }
            } else if (latestToken != null && isHeaderAuth(msg.getRequestingUser())) {
                // Always update the token for the other senders (apart from the modern spiders,
                // which handle auth themselves)
                msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, latestToken);
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
        hostToToken.clear();
    }

    /* Just for testing */
    protected int getHostCount() {
        return hostToToken.size();
    }

    /* Just for testing */
    protected String getTokenForHost(String host) {
        return hostToToken.get(host);
    }
}
