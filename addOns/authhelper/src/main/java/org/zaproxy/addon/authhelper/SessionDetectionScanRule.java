/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.HeaderBasedSessionManagementMethodType.HeaderBasedSessionManagementMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthCheckingStrategy;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.Stats;

public class SessionDetectionScanRule extends PluginPassiveScanner {

    public static final int PLUGIN_ID = 10112;

    private static final Logger LOGGER = LogManager.getLogger(SessionDetectionScanRule.class);

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public boolean appliesToHistoryType(int historyType) {
        return ExtensionAuthhelper.HISTORY_TYPES_SET.contains(historyType);
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (!AuthUtils.isRelevantToAuth(msg)) {
            return;
        }
        Map<String, SessionToken> responseTokens = AuthUtils.getResponseSessionTokens(msg);

        if (!responseTokens.isEmpty()) {
            // The response looks like it contains session tokens
            SessionManagementRequestDetails smDetails =
                    new SessionManagementRequestDetails(
                            msg, new ArrayList<>(responseTokens.values()), Alert.CONFIDENCE_MEDIUM);
            LOGGER.debug(
                    "Found {} response session token(s) in {}",
                    responseTokens.size(),
                    msg.getRequestHeader().getURI());
            processSessionMgmtDetailsTokens(smDetails);
        }
        Set<SessionToken> requestTokens = AuthUtils.getRequestSessionTokens(msg);
        LOGGER.debug(
                "Identified {} request token(s) in {}",
                requestTokens.size(),
                msg.getRequestHeader().getURI());
        if (!requestTokens.isEmpty()) {
            // The request is using at least one session token, do we know where they come from?
            List<SessionToken> foundTokens = new ArrayList<>();
            for (SessionToken st : requestTokens) {
                SessionToken sourceToken = AuthUtils.containsSessionToken(st.getValue());
                if (sourceToken == null) {
                    SessionManagementRequestDetails smrd =
                            AuthUtils.findSessionTokenSource(st.getValue());
                    if (smrd != null) {
                        processSessionMgmtDetailsTokens(smrd);
                        foundTokens.addAll(smrd.getTokens());
                    } else {
                        LOGGER.debug("Failed to find source of {}", st.getKey());
                    }
                } else {
                    foundTokens.add(sourceToken);
                    LOGGER.debug("Found source of {}", st.getKey());
                }
            }
            LOGGER.debug(
                    "Found a total of {} request token(s) in {}",
                    foundTokens.size(),
                    msg.getRequestHeader().getURI());
            if (!foundTokens.isEmpty()) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "Found sources of session management tokens in {}:",
                            msg.getRequestHeader().getURI());
                    foundTokens.forEach(t -> LOGGER.debug("Found tokens {}", t.getToken()));
                }
                List<Context> contextList = AuthUtils.getRelatedContexts(msg);
                SessionManagementRequestDetails smDetails =
                        new SessionManagementRequestDetails(
                                msg, foundTokens, Alert.CONFIDENCE_MEDIUM);

                for (Context context : contextList) {
                    if (isBetterAutoDetectSessionMagagement(context, smDetails)) {
                        // Reconfigure the session for the found session management method
                        AuthUtils.setSessionManagementDetailsForContext(context.getId(), smDetails);
                        LOGGER.debug(
                                "Auto updating session management for context {}:",
                                context.getName());
                        HeaderBasedSessionManagementMethodType type =
                                new HeaderBasedSessionManagementMethodType();
                        HeaderBasedSessionManagementMethod method =
                                type.createSessionManagementMethod(context.getId());
                        method.setHeaderConfigs(AuthUtils.getHeaderTokens(msg, foundTokens, true));

                        context.setSessionManagementMethod(method);
                        Stats.incCounter("stats.auth.configure.session.header");

                        if (context.getAuthenticationMethod().getAuthCheckingStrategy()
                                == AuthCheckingStrategy.AUTO_DETECT) {
                            AuthUtils.setVerificationDetailsForContext(
                                    context.getId(), new VerificationRequestDetails());
                        }
                    }
                }
            } else if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(
                        "Failed to find source of session management tokens in {}:",
                        msg.getRequestHeader().getURI());
                requestTokens.forEach(st -> LOGGER.debug("Missed token {}", st.getToken()));
            }
        }
    }

    private void processSessionMgmtDetailsTokens(SessionManagementRequestDetails smDetails) {
        getAlert(smDetails).raise();
        smDetails
                .getTokens()
                .forEach(
                        t -> {
                            AuthUtils.recordSessionToken(t);
                            Stats.incCounter("stats.auth.detect.session." + t.getKey());
                        });
    }

    /**
     * Returns true if the context has been set to "auto detect" session management and the supplied
     * SessionManagementRequestDetails is a better match than the previously found one.
     */
    protected boolean isBetterAutoDetectSessionMagagement(
            Context context, SessionManagementRequestDetails smDetails) {
        if (context.getSessionManagementMethod().getType()
                instanceof AutoDetectSessionManagementMethodType) {
            return true;
        }
        SessionManagementRequestDetails currentReq =
                AuthUtils.getSessionManagementDetailsForContext(context.getId());
        return currentReq != null && smDetails.getTokens().size() > currentReq.getTokens().size();
    }

    protected AlertBuilder getAlert(SessionManagementRequestDetails smDetails) {
        // Base param and evidence on the first token - there will always be at least one
        SessionToken token = smDetails.getTokens().get(0);

        return newAlert()
                .setMessage(smDetails.getMsg())
                .setRisk(Alert.RISK_INFO)
                .setConfidence(smDetails.getConfidence())
                .setParam(token.getKey())
                .setEvidence(token.getKey())
                .setDescription(Constant.messages.getString("authhelper.session-detect.desc"))
                .setSolution(Constant.messages.getString("authhelper.session-detect.soln"))
                .setReference(
                        "https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/")
                .setOtherInfo(
                        smDetails.getTokens().stream()
                                .map(SessionToken::getToken)
                                .collect(Collectors.joining("\n")));
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        List<SessionToken> tokens = new ArrayList<>();
        tokens.add(new SessionToken(SessionToken.HEADER_SOURCE, HttpHeader.AUTHORIZATION, ""));
        SessionManagementRequestDetails smDetails =
                new SessionManagementRequestDetails(null, tokens, Alert.CONFIDENCE_MEDIUM);
        alerts.add(this.getAlert(smDetails).build());
        return alerts;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("authhelper.session-detect.name");
    }
}
