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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.paros.ParosDatabaseServer;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.authentication.AuthenticationHelper;

/** A very thin layer on top of the History functionality, to make testing easier. */
public class HistoryProvider implements SessionChangedListener {

    private static final int MAX_NUM_RECORDS_TO_CHECK = 200;

    private static final Logger LOGGER = LogManager.getLogger(HistoryProvider.class);

    private static final String QUERY_SESS_MGMT_TOKEN_MSG_IDS =
            """
            SELECT HISTORYID FROM HISTORY
            WHERE HISTORYID BETWEEN ? AND ?
            AND (
                POSITION(? IN RESHEADER) > 0
                OR POSITION(? IN RESBODY) > 0
                OR POSITION(? IN REQHEADER) > 0
                OR POSITION(? IN REQHEADER) > 0 -- URLEncoded
                OR POSITION(? IN RESBODY) > 0 -- JSONEscaped
            )
            ORDER BY HISTORYID DESC
            """;

    private ParosDatabaseServer pds;
    private boolean server;

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

    /**
     * The query is ordered DESCending so the List and subsequent processing should be newest
     * message first.
     */
    List<Integer> getMessageIds(int first, int last, String value) {
        if (!server) {
            server = true;
            if (Model.getSingleton().getDb().getDatabaseServer()
                    instanceof ParosDatabaseServer pdbs) {
                pds = pdbs;
            } else {
                LOGGER.warn("Unsupported Database Server.");
            }
        }
        if (pds == null) {
            return List.of();
        }

        try (PreparedStatement psGetHistory =
                pds.getSingletonConnection().prepareStatement(QUERY_SESS_MGMT_TOKEN_MSG_IDS)) {
            psGetHistory.setInt(1, first);
            psGetHistory.setInt(2, last);
            psGetHistory.setString(3, value);
            psGetHistory.setBytes(4, value.getBytes(StandardCharsets.UTF_8));
            psGetHistory.setString(5, value);
            psGetHistory.setString(6, URLEncoder.encode(value, StandardCharsets.UTF_8));
            psGetHistory.setBytes(
                    7, StringEscapeUtils.escapeJson(value).getBytes(StandardCharsets.UTF_8));

            List<Integer> msgIds = new ArrayList<>();
            try (ResultSet rs = psGetHistory.executeQuery()) {
                while (rs.next()) {
                    msgIds.add(rs.getInt("HISTORYID"));
                }
            } catch (SQLException e) {
                LOGGER.warn("Failed to process result set. {}", e.getMessage());
            }
            LOGGER.debug("Found: {} candidate messages for {}", msgIds.size(), value);
            return msgIds;
        } catch (SQLException e) {
            LOGGER.warn("Failed to prepare query.", e);
            return List.of();
        }
    }

    public int getLastHistoryId() {
        return getExtHistory().getLastHistoryId();
    }

    public SessionManagementRequestDetails findSessionTokenSource(String token, int firstId) {
        int lastId = getLastHistoryId();
        if (firstId == -1) {
            firstId = Math.max(1, lastId - MAX_NUM_RECORDS_TO_CHECK);
        }

        LOGGER.debug("Searching for session token from {} down to {} ", lastId, firstId);

        for (int id : getMessageIds(firstId, lastId, token)) {
            try {
                HttpMessage msg = getHttpMessage(id);
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

    @Override
    public void sessionChanged(Session session) {
        pds = null;
        server = false;
    }

    @Override
    public void sessionAboutToChange(Session session) {
        // Nothing to do
    }

    @Override
    public void sessionScopeChanged(Session session) {
        // Nothing to do
    }

    @Override
    public void sessionModeChanged(Mode mode) {
        // Nothing to do
    }
}
