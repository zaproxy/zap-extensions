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
import java.util.Map.Entry;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.HeaderBasedSessionManagementMethodType.HeaderBasedSessionManagementMethod;
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
        SessionManagementRequestDetails smDetails = null;
        Map<String, SessionToken> responseTokens = AuthUtils.getResponseSessionTokens(msg);

        if (!responseTokens.isEmpty()) {
            // The response looks like it contains session tokens
            smDetails =
                    new SessionManagementRequestDetails(
                            msg, new ArrayList<>(responseTokens.values()), Alert.CONFIDENCE_MEDIUM);
            getAlert(smDetails).raise();
            smDetails.getTokens().forEach(t -> AuthUtils.recordSessionToken(t));
        }
        Map<String, SessionToken> requestTokens = AuthUtils.getRequestSessionTokens(msg);
        if (!requestTokens.isEmpty()) {
            // The request is using at least one session token, do we know where they come from?
            List<SessionToken> foundTokens = new ArrayList<>();
            for (Entry<String, SessionToken> entry : requestTokens.entrySet()) {
                SessionToken sourceToken = AuthUtils.containsSessionToken(entry.getKey());
                if (sourceToken != null) {
                    foundTokens.add(sourceToken);
                }
            }

            if (foundTokens.isEmpty()) {
                // These are not 'known' session tokens, see if we can find any of them
                for (Entry<String, SessionToken> entry : requestTokens.entrySet()) {
                    SessionManagementRequestDetails smrd =
                            AuthUtils.findSessionTokenSource(entry.getKey());
                    if (smrd != null) {
                        // Yes, found the token in a 'non standard' place
                        this.getTaskHelper()
                                .raiseAlert(smrd.getMsg().getHistoryRef(), getAlert(smrd).build());
                        foundTokens = smrd.getTokens();
                        break;
                    }
                }
            }
            if (!foundTokens.isEmpty()) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "Found sources of session management tokens in {}:",
                            msg.getRequestHeader().getURI());
                    foundTokens.forEach(t -> LOGGER.debug("Found tokens {}", t.getToken()));
                }
                List<Context> contextList =
                        Model.getSingleton()
                                .getSession()
                                .getContextsForUrl(msg.getRequestHeader().getURI().toString());
                for (Context context : contextList) {
                    if (context.getSessionManagementMethod().getType()
                            instanceof AutoDetectSessionManagementMethodType) {
                        // Reconfigure the session for the found session management method
                        LOGGER.debug(
                                "Auto updating session management for context {}:",
                                context.getName());
                        HeaderBasedSessionManagementMethodType type =
                                new HeaderBasedSessionManagementMethodType();
                        HeaderBasedSessionManagementMethod method =
                                type.createSessionManagementMethod(context.getId());
                        method.setHeaderConfigs(AuthUtils.getHeaderTokens(msg, foundTokens));
                        context.setSessionManagementMethod(method);
                        Stats.incCounter("stats.auth.configure.session.header");
                    }
                }
                foundTokens.forEach(t -> AuthUtils.removeSessionToken(t));
            } else if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(
                        "Failed to find source of session management tokens in {}:",
                        msg.getRequestHeader().getURI());
                requestTokens.forEach((t, st) -> LOGGER.debug("Missed token {}", st.getToken()));
            }
        }
    }

    protected AlertBuilder getAlert(SessionManagementRequestDetails smDetails) {
        StringBuilder sb = new StringBuilder();
        smDetails.getTokens().stream().forEach(t -> sb.append("\n").append(t.getToken()));

        // Base param and evidence on the first token - there will always be at least one
        SessionToken token = smDetails.getTokens().get(0);

        return newAlert()
                .setMessage(smDetails.getMsg())
                .setRisk(Alert.RISK_INFO)
                .setConfidence(smDetails.getConfidence())
                .setParam(token.getKey())
                .setEvidence(token.getValue())
                .setDescription(Constant.messages.getString("authhelper.session-detect.desc"))
                .setSolution(Constant.messages.getString("authhelper.session-detect.soln"))
                .setReference("https://www.zaproxy.org/docs/desktop/addons/authentication-helper/")
                .setOtherInfo(sb.toString());
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<SessionToken> tokens = new ArrayList<>();
        tokens.add(new SessionToken(SessionToken.HEADER_TYPE, HttpHeader.AUTHORIZATION, ""));
        SessionManagementRequestDetails smDetails =
                new SessionManagementRequestDetails(null, null, Alert.CONFIDENCE_MEDIUM);
        return List.of(this.getAlert(smDetails).build());
    }

    @Override
    public String getName() {
        return Constant.messages.getString("authhelper.session-detect.name");
    }
}
