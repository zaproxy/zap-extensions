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
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.SessionManagementRequestDetails;
import org.zaproxy.addon.authhelper.SessionToken;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.model.Context;

public final class ClientSideHandler implements HttpMessageHandler {

    private static final Logger LOGGER = LogManager.getLogger(ClientSideHandler.class);

    private final Context context;
    private HttpMessage authMsg;
    private HttpMessage fallbackMsg;
    private int firstHrefId;

    public ClientSideHandler(Context context) {
        this.context = context;
    }

    private boolean isPost(HttpMessage msg) {
        return HttpRequestHeader.POST.equals(msg.getRequestHeader().getMethod());
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {

        if (ctx.isFromClient()) {
            return;
        }

        AuthenticationHelper.addAuthMessageToHistory(msg);

        if (isPost(msg) && context.isIncluded(msg.getRequestHeader().getURI().toString())) {
            // Record the last in scope POST as a fallback
            fallbackMsg = msg;
        }

        if (authMsg != null && isPost(authMsg) && !isPost(msg)) {
            // We have a better candidate
            return;
        }

        SessionManagementRequestDetails smReqDetails = null;
        Map<String, SessionToken> sessionTokens = AuthUtils.getResponseSessionTokens(msg);
        if (!sessionTokens.isEmpty()) {
            authMsg = msg;
            LOGGER.debug(
                    "Session token found in href {} {}",
                    authMsg.getHistoryRef().getHistoryId(),
                    isPost(msg));
            smReqDetails =
                    new SessionManagementRequestDetails(
                            authMsg,
                            new ArrayList<>(sessionTokens.values()),
                            Alert.CONFIDENCE_HIGH);
        } else {
            Set<SessionToken> reqSessionTokens = AuthUtils.getRequestSessionTokens(msg);
            if (!reqSessionTokens.isEmpty()) {
                // The request has at least one auth token we missed - try
                // to find one of them
                for (SessionToken st : reqSessionTokens) {
                    smReqDetails = AuthUtils.findSessionTokenSource(st.getValue(), firstHrefId);
                    if (smReqDetails != null) {
                        authMsg = smReqDetails.getMsg();
                        LOGGER.debug(
                                "Session token found in href {}",
                                authMsg.getHistoryRef().getHistoryId());
                        break;
                    }
                }
            }

            if (authMsg != null && View.isInitialised()) {
                String hrefId = "?";
                if (msg.getHistoryRef() != null) {
                    hrefId = "" + msg.getHistoryRef().getHistoryId();
                }
                AuthUtils.logUserMessage(
                        Level.INFO,
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.output.sessionid", hrefId));
            }
        }
        if (firstHrefId == 0 && msg.getHistoryRef() != null) {
            firstHrefId = msg.getHistoryRef().getHistoryId();
        }
    }

    public HttpMessage getAuthMsg() {
        return authMsg;
    }

    public void resetAuthMsg() {
        this.authMsg = null;
    }

    public HttpMessage getFallbackMsg() {
        return fallbackMsg;
    }
}
