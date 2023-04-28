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
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.VerificationRequestDetails.VerificationComparator;
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
        Set<SessionToken> sessionTokens = AuthUtils.getRequestSessionTokens(msg);
        if (sessionTokens.isEmpty()) {
            return;
        }
        // We have at least one session token, so it might be of interest

        for (SessionToken st : sessionTokens) {
            String token = st.getValue();

            List<Context> contextList = AuthUtils.getRelatedContexts(msg);

            for (Context context : contextList) {
                VerificationRequestDetails currentVerifDetails =
                        AuthUtils.getVerificationDetailsForContext(context.getId());
                VerificationRequestDetails newVerfiDetails =
                        new VerificationRequestDetails(msg, token, context);
                if (currentVerifDetails != null
                        && COMPARATOR.compare(newVerfiDetails, currentVerifDetails) > 0) {
                    // We've potentially found a better verification request
                    LOGGER.debug(
                            "Identified potentially better verification req {} for context {}",
                            msg.getRequestHeader().getURI(),
                            context.getName());
                    AuthUtils.processVerificationDetails(context, newVerfiDetails, this);
                }
            }
        }
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
                        "https://www.zaproxy.org/docs/desktop/addons/authentication-helper/verif-id");
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
