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
package org.zaproxy.addon.authhelper.internal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.ExtensionAuthhelper;
import org.zaproxy.addon.authhelper.HeaderBasedSessionManagementMethodType;
import org.zaproxy.addon.authhelper.HistoryProvider;
import org.zaproxy.addon.authhelper.SessionManagementRequestDetails;
import org.zaproxy.addon.authhelper.SessionToken;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.Pair;

public final class ClientSideHandler implements HttpMessageHandler {

    private static final Logger LOGGER = LogManager.getLogger(ClientSideHandler.class);

    private static Pattern KV_PAIR_PATTERN = Pattern.compile("\\{%([^:]+):([^%]+)%}");

    private final User user;
    private UsernamePasswordAuthenticationCredentials authCreds;
    private AuthRequestDetails authReq;
    private int firstHrefId;

    @Setter private HistoryProvider historyProvider = ExtensionAuthhelper.getHistoryProvider();

    public ClientSideHandler(User user) {
        this.user = user;
        if (user.getAuthenticationCredentials()
                instanceof UsernamePasswordAuthenticationCredentials authCred) {
            this.authCreds = authCred;
        }
    }

    private boolean isPost(HttpMessage msg) {
        return HttpRequestHeader.POST.equals(msg.getRequestHeader().getMethod());
    }

    private boolean containsMaybeEncodedString(String contents, String testStr) {
        return contents.contains(testStr)
                || contents.contains(ExtensionAuthhelper.urlEncode(testStr));
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {

        if (ctx.isFromClient()) {
            return;
        }
        if (firstHrefId == 0 && msg.getHistoryRef() != null) {
            // Backstop for looping back through the history
            firstHrefId = msg.getHistoryRef().getHistoryId();
        }

        historyProvider.addAuthMessageToHistory(msg);

        if (!user.getContext().isIncluded(msg.getRequestHeader().getURI().toString())) {
            String reqBody = msg.getRequestBody().toString();
            if (isPost(msg)
                    && authCreds != null
                    && StringUtils.isNotEmpty(authCreds.getUsername())
                    && StringUtils.isNotEmpty(authCreds.getPassword())
                    && containsMaybeEncodedString(reqBody, authCreds.getUsername())
                    && containsMaybeEncodedString(reqBody, authCreds.getPassword())
                    && AuthUtils.getSessionManagementDetailsForContext(user.getContext().getId())
                            != null
                    && !AuthUtils.isAuthProvider(msg)) {
                // The app is sending user creds to another site. Assume this is part of the valid
                // auth flow and add to the context
                try {
                    String site = SessionStructure.getHostName(msg);
                    user.getContext().addIncludeInContextRegex(site + ".*");
                    LOGGER.info(
                            "Adding site {} to context, as configured for session auto-detection and credentials posted to it",
                            site);
                } catch (URIException e) {
                    // Very unexpected
                    LOGGER.error(e.getMessage(), e);
                    return;
                }
            } else {
                // Not in the context, no creds, not relevant
                return;
            }
        }
        AuthRequestDetails candidate = new AuthRequestDetails(msg);

        List<Pair<String, String>> headerConfigs = null;

        if (user.getContext().getSessionManagementMethod()
                instanceof
                HeaderBasedSessionManagementMethodType.HeaderBasedSessionManagementMethod smgmt) {
            headerConfigs = smgmt.getHeaderConfigs();
        }

        if (candidate.isBetterThan(authReq, headerConfigs)) {
            LOGGER.debug(
                    "Found better auth candidate {} {}",
                    msg.getRequestHeader().getMethod(),
                    msg.getRequestHeader().getURI());
            authReq = candidate;
        }

        Set<SessionToken> reqSessionTokens = AuthUtils.getRequestSessionTokens(msg, headerConfigs);
        Set<SessionToken> unkSessionTokens = new HashSet<>();
        for (SessionToken token : reqSessionTokens) {
            if (!SessionToken.COOKIE_SOURCE.equals(token.getSource())) {
                AuthUtils.recordRequestSessionToken(
                        user.getContext(), token.getKey(), token.getValue());
            }
            if (AuthUtils.containsSessionToken(token.getValue()) == null) {
                unkSessionTokens.add(token);
            }
        }
        for (SessionToken st : unkSessionTokens) {
            // See if we can find the reqs for the unknown session tokens, then see if they are
            // better than the current one
            SessionManagementRequestDetails smReqDetails =
                    AuthUtils.findSessionTokenSource(st.getValue(), firstHrefId);
            if (smReqDetails != null) {
                candidate = new AuthRequestDetails(msg);
                if (candidate.isBetterThan(authReq, headerConfigs)) {
                    LOGGER.debug(
                            "Found better auth candidate {} {}",
                            msg.getRequestHeader().getMethod(),
                            msg.getRequestHeader().getURI());
                    authReq = candidate;
                }
            }
        }
    }

    protected AuthRequestDetails getAuthReqDetails() {
        return authReq;
    }

    public HttpMessage getAuthMsg() {
        if (authReq != null) {
            return authReq.getMsg();
        }
        return null;
    }

    public void resetAuthMsg() {
        this.authReq = null;
    }

    protected static boolean isBetterThan(
            SessionManagementRequestDetails smrd1, SessionManagementRequestDetails smrd2) {
        if (smrd2 == null) {
            return true;
        }
        if (smrd1.getConfidence() > smrd2.getConfidence()) {
            return true;
        }
        if (smrd1.getConfidence() < smrd2.getConfidence()) {
            return false;
        }
        return smrd1.getTokens().size() > smrd2.getTokens().size();
    }

    protected static List<Pair<String, String>> extractKeyValuePairs(String input) {
        List<Pair<String, String>> keyValuePairs = new ArrayList<>();
        Matcher matcher = KV_PAIR_PATTERN.matcher(input);

        while (matcher.find()) {
            keyValuePairs.add(new Pair<>(matcher.group(1), matcher.group(2)));
        }

        return keyValuePairs;
    }

    protected static int messageTokenCount(HttpMessage msg, List<Pair<String, String>> kvPairs) {
        int count = 0;
        Collection<SessionToken> tokens = AuthUtils.getAllTokens(msg, false).values();

        for (Pair<String, String> kvPair : kvPairs) {
            for (SessionToken token : tokens) {
                if (token.getSource().equals(kvPair.first)
                        && token.getKey().equals(kvPair.second)) {
                    count++;
                    break;
                }
            }
        }
        return count;
    }

    @Getter
    class AuthRequestDetails {
        private HttpMessage msg;
        private boolean incUsername;
        private boolean incPassword;

        public AuthRequestDetails(HttpMessage msg) {
            this.msg = msg;
            String body = msg.getRequestBody().toString();
            incUsername =
                    authCreds != null
                            && StringUtils.isNotBlank(authCreds.getUsername())
                            && containsMaybeEncodedString(body, authCreds.getUsername());
            incPassword =
                    authCreds != null
                            && StringUtils.isNotBlank(authCreds.getPassword())
                            && containsMaybeEncodedString(body, authCreds.getPassword());
        }

        /**
         * Is this a better candidate for the authentication request than the supplied
         * AuthRequestDetails.
         *
         * @param ard the details to compare with
         * @param headerConfigs - cannot cache these as they may change when session management
         *     auto-detect used
         * @return true if this is a better candidate than the supplied one.
         */
        public boolean isBetterThan(
                AuthRequestDetails ard, List<Pair<String, String>> headerConfigs) {
            int statusCode = msg.getResponseHeader().getStatusCode();
            if (HttpStatusCode.isClientError(statusCode)
                    || HttpStatusCode.isServerError(statusCode)) {
                // Ignore all error responses
                return false;
            }
            if (ard == null) {
                return true;
            }
            // Including the right tokens is the most important thing, assuming there are any
            // relevant ones
            if (headerConfigs != null) {
                List<Pair<String, String>> kvPairs = new ArrayList<>();
                for (Pair<String, String> pair : headerConfigs) {
                    if (HttpHeader.COOKIE.equalsIgnoreCase(pair.first)) {
                        // We track cookies directly
                        continue;
                    }
                    // Most of the time we'd just expect one token, but we need to cope with an
                    // arbitrary number
                    kvPairs.addAll(extractKeyValuePairs(pair.second));
                }
                if (messageTokenCount(msg, kvPairs) > messageTokenCount(ard.getMsg(), kvPairs)) {
                    return true;
                }
            }
            if (this.incPassword && !ard.incPassword) {
                return true;
            }
            if (this.incUsername && !ard.incUsername) {
                return true;
            }
            if (isPost(msg) && !isPost(ard.getMsg())) {
                return true;
            }
            // Default to the current one so we always choose the oldest most relevant request
            return false;
        }
    }
}
