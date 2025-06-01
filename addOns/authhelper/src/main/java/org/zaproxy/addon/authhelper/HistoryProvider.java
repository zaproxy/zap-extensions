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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.authentication.AuthenticationHelper;

/** A very thin layer on top of the History functionality, to make testing easier. */
public class HistoryProvider {

    private static final int MAX_NUM_RECORDS_TO_CHECK = 200;

    private static final Logger LOGGER = LogManager.getLogger(HistoryProvider.class);

    private ExtensionHistory extHist;

    private ExtensionHistory getExtHistory() {
        if (extHist == null) {
            extHist = AuthUtils.getExtension(ExtensionHistory.class);
        }
        return extHist;
    }

    public void addAuthMessageToHistory(HttpMessage msg) {
        AuthenticationHelper.addAuthMessageToHistory(msg);
    }

    public HttpMessage getHttpMessage(int historyId)
            throws HttpMalformedHeaderException, DatabaseException {
        HistoryReference hr = getExtHistory().getHistoryReference(historyId);
        if (hr != null) {
            return hr.getHttpMessage();
        }
        return null;
    }

    public int getLastHistoryId() {
        return getExtHistory().getLastHistoryId();
    }

    public SessionManagementRequestDetails findSessionTokenSource(String token, int firstId) {
        int lastId = getLastHistoryId();
        if (firstId == -1) {
            firstId = Math.max(0, lastId - MAX_NUM_RECORDS_TO_CHECK);
        }

        LOGGER.debug("Searching for session token from {} down to {} ", lastId, firstId);

        for (int i = lastId; i >= firstId; i--) {
            try {
                HttpMessage msg = getHttpMessage(i);
                if (msg == null) {
                    continue;
                }
                Optional<SessionToken> es =
                        AuthUtils.getAllTokens(msg, false).values().stream()
                                .filter(v -> v.getValue().equals(token))
                                .findFirst();
                if (es.isPresent()) {
                    AuthUtils.incStatsCounter(
                            msg.getRequestHeader().getURI(),
                            AuthUtils.AUTH_SESSION_TOKEN_STATS_PREFIX + es.get().getKey());
                    List<SessionToken> tokens = new ArrayList<>();
                    tokens.add(
                            new SessionToken(
                                    es.get().getSource(), es.get().getKey(), es.get().getValue()));
                    return new SessionManagementRequestDetails(msg, tokens, Alert.CONFIDENCE_HIGH);
                }
            } catch (Exception e) {
                LOGGER.debug(e.getMessage(), e);
            }
        }
        return null;
    }
}
