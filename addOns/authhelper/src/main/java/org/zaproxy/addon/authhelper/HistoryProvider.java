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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
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
            -- AND (
            --     POSITION(? IN RESHEADER) > 0
            --     OR POSITION(? IN RESBODY) > 0
            --     OR POSITION(? IN REQHEADER) > 0
            -- )
            ORDER BY HISTORYID DESC
            """;

    private static PreparedStatement psGetHistory;

    private ParosDatabaseServer pds;
    private boolean warnedNonParosDb;

    private ExtensionHistory extHist;

    HistoryProvider() {
        getParaosDataBaseServer();
    }

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
        Connection conn = getDbConnection();
        if (conn == null) {
            return List.of();
        }
        PreparedStatement query = getHistoryQuery(first, last, value, conn);
        if (query == null) {
            return List.of();
        }
        List<Integer> msgIds = new ArrayList<>();

        try (ResultSet rs = psGetHistory.executeQuery()) {
            while (rs.next()) {
                msgIds.add(rs.getInt("HISTORYID"));
            }
        } catch (SQLException e) {
            LOGGER.warn("Failed to process result set.");
        }
        LOGGER.debug("Found: {} candidate messages for {}", msgIds.size(), value);
        LOGGER.info("{} IDs", msgIds.size());
        return msgIds;
    }

    private static PreparedStatement getHistoryQuery(
            int first, int last, String value, Connection conn) {
        try {
            if (psGetHistory == null || psGetHistory.isClosed()) {
                psGetHistory = conn.prepareStatement(QUERY_SESS_MGMT_TOKEN_MSG_IDS);
                psGetHistory.setInt(1, first);
                psGetHistory.setInt(2, last);
                //                psGetHistory.setString(3, value);
                //                psGetHistory.setBytes(4, value.getBytes(StandardCharsets.UTF_8));
                //                psGetHistory.setString(5, value);
            }
        } catch (SQLException e) {
            LOGGER.warn("Failed to prepare query.", e);
        }
        return psGetHistory;
    }

    private Connection getDbConnection() {
        if (pds == null) {
            LOGGER.info("PDS was null");
            return null;
        }
        Connection conn = null;
        try {
            conn = pds.getSingletonConnection();
        } catch (SQLException | NullPointerException e) {
            LOGGER.warn("Failed to get DB connection.", e);
        }
        return conn;
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

    private ParosDatabaseServer getParaosDataBaseServer() {
        if (Model.getSingleton().getDb().getDatabaseServer() instanceof ParosDatabaseServer pdbs) {
            pds = pdbs;
            LOGGER.info("PDS ? {}", pds != null);
        } else {
            if (pds == null && !warnedNonParosDb) {
                LOGGER.warn("Unexpected Database Server.");
                warnedNonParosDb = true;
            }
        }
        return pds;
    }

    @Override
    public void sessionChanged(Session session) {
        pds = null;
        warnedNonParosDb = false;
        getParaosDataBaseServer();
    }

    @Override
    public void sessionAboutToChange(Session session) {
        try {
            if (psGetHistory != null) {
                psGetHistory.close();
            }
        } catch (SQLException e) {
            // Nothing to do
        }
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
