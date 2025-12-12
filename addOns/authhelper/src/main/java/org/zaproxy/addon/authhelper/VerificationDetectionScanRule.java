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

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang3.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.authhelper.VerificationRequestDetails.VerificationComparator;
import org.zaproxy.addon.commonlib.AuthConstants;
import org.zaproxy.addon.network.NetworkUtils;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Context;

public class VerificationDetectionScanRule extends PluginPassiveScanner {

    public static final int PLUGIN_ID = 10113;

    private static final Logger LOGGER = LogManager.getLogger(VerificationDetectionScanRule.class);

    private static final VerificationComparator COMPARATOR =
            VerificationRequestDetails.getComparator();

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

        if (!AuthUtils.isRelevantToAuth(msg) || isPoorCandidate(msg)) {
            return;
        }
        if (!HttpRequestHeader.GET.equals(msg.getRequestHeader().getMethod())
                && !HttpRequestHeader.POST.equals(msg.getRequestHeader().getMethod())) {
            // These are the only 2 methods currently supported
            return;
        }

        boolean lowPriority = isLowPriority(msg);
        Set<SessionToken> sessionTokens = AuthUtils.getRequestSessionTokens(msg);
        if (sessionTokens.isEmpty()) {
            if (NetworkUtils.isHttpBasicAuth(msg) || NetworkUtils.isHttpDigestAuth(msg)) {
                List<Context> contextList = AuthUtils.getRelatedContexts(msg);

                for (Context context : contextList) {
                    VerificationRequestDetails currentVerifDetails =
                            AuthUtils.getVerificationDetailsForContext(context.getId());
                    VerificationRequestDetails newVerifDetails =
                            new VerificationRequestDetails(
                                    msg,
                                    msg.getRequestHeader().getHeader(HttpHeader.AUTHORIZATION),
                                    context);
                    newVerifDetails.setLowPriority(lowPriority);
                    if (currentVerifDetails != null
                            && newVerifDetails.getScore() > 0
                            && COMPARATOR.compare(newVerifDetails, currentVerifDetails) > 0) {
                        // We've potentially found a better verification request
                        LOGGER.debug(
                                "Identified potentially better verification req {} for context {}",
                                msg.getRequestHeader().getURI(),
                                context.getName());
                        AuthUtils.processVerificationDetails(context, newVerifDetails, this);
                    }
                }
            }

            return;
        }
        // We have at least one session token, so it might be of interest
        for (SessionToken st : sessionTokens) {
            String token = st.getValue();

            List<Context> contextList = AuthUtils.getRelatedContexts(msg);

            for (Context context : contextList) {
                VerificationRequestDetails currentVerifDetails =
                        AuthUtils.getVerificationDetailsForContext(context.getId());
                VerificationRequestDetails newVerifDetails =
                        new VerificationRequestDetails(msg, token, context);
                newVerifDetails.setLowPriority(lowPriority);
                if (currentVerifDetails != null
                        && newVerifDetails.getScore() > 0
                        && COMPARATOR.compare(newVerifDetails, currentVerifDetails) > 0) {
                    // We've potentially found a better verification request
                    LOGGER.debug(
                            "Identified potentially better verification req {} for context {}",
                            msg.getRequestHeader().getURI(),
                            context.getName());
                    AuthUtils.processVerificationDetails(context, newVerifDetails, this);
                }
            }
        }
    }

    private static boolean isPoorCandidate(HttpMessage msg) {
        String escapedPathQuery = msg.getRequestHeader().getURI().getEscapedPathQuery();
        return Stream.concat(
                        AuthConstants.getLogoutIndicators().stream(),
                        AuthConstants.getRegistrationIndicators().stream())
                .anyMatch(keyword -> Strings.CI.contains(escapedPathQuery, keyword));
    }

    private static boolean isLowPriority(HttpMessage msg) {
        String escapedPathQuery = msg.getRequestHeader().getURI().getEscapedPathQuery();
        return AuthConstants.getLoginIndicators().stream()
                .anyMatch(keyword -> Strings.CI.contains(escapedPathQuery, keyword));
    }

    protected AlertBuilder getAlert(VerificationRequestDetails verifDetails) {
        return newAlert()
                .setMessage(verifDetails.getMsg())
                .setRisk(Alert.RISK_INFO)
                .setConfidence(verifDetails.getConfidence())
                .setEvidence(verifDetails.getEvidence())
                .setDescription(Constant.messages.getString("authhelper.verification-detect.desc"))
                .setSolution(Constant.messages.getString("authhelper.verification-detect.soln"))
                .setReference(
                        "https://www.zaproxy.org/docs/desktop/addons/authentication-helper/verification-id/");
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(getAlert(new VerificationRequestDetails()).build());
    }

    @Override
    public String getName() {
        return Constant.messages.getString("authhelper.verification-detect.name");
    }
}
