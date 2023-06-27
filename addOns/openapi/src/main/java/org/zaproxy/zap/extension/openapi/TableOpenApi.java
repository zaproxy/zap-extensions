/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hsqldb.jdbc.JDBCClob;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DbUtils;
import org.parosproxy.paros.db.paros.ParosAbstractTable;

public class TableOpenApi extends ParosAbstractTable {

    private static final Logger LOGGER = LogManager.getLogger(TableOpenApi.class);

    private PreparedStatement psInsertOpenApiSpec;
    private PreparedStatement psSelectOpenApiSpecsForContext;
    private PreparedStatement psDeleteOpenApiSpecForContext;

    @Override
    protected void reconnect(Connection conn) throws DatabaseException {
        try {
            if (!DbUtils.hasTable(conn, "OPENAPI_SPECS")) {
                DbUtils.execute(
                        conn,
                        "CREATE CACHED TABLE openapi_specs ("
                                + "id INT NOT NULL IDENTITY, "
                                + "definition CLOB(64M) NOT NULL, "
                                + "target NVARCHAR(2048), "
                                + "session_id BIGINT NOT NULL, "
                                + "context_id INT NOT NULL, "
                                + "PRIMARY KEY (id))");
            } else {
                updateTable(conn);
            }
            psInsertOpenApiSpec =
                    conn.prepareStatement(
                            "INSERT INTO openapi_specs (definition, target, session_id, context_id) VALUES (?, ?, ?, ?)");
            psSelectOpenApiSpecsForContext =
                    conn.prepareStatement(
                            "SELECT definition, target, session_id, context_id "
                                    + "FROM openapi_specs WHERE context_id = ?");
            psDeleteOpenApiSpecForContext =
                    conn.prepareStatement("DELETE FROM openapi_specs WHERE context_id = ?");
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    private static void updateTable(Connection conn) {
        try {
            int columnSize = DbUtils.getColumnSize(conn, "OPENAPI_SPECS", "DEFINITION");
            if (columnSize < 17_000_000) {
                LOGGER.debug("Definition column size was: {}", columnSize);
                increaseDefinitionColumnSize(conn);
            }
        } catch (SQLException e) {
            LOGGER.debug("Couldn't get definition column size.", e);
        }
    }

    private static void increaseDefinitionColumnSize(Connection conn) {
        try {
            DbUtils.execute(conn, "ALTER TABLE openapi_specs ALTER COLUMN definition CLOB(64M)");
            int columnSize = DbUtils.getColumnSize(conn, "OPENAPI_SPECS", "DEFINITION");
            LOGGER.debug("Definition column size is now: {}", columnSize);
        } catch (SQLException e) {
            LOGGER.warn(e);
        }
    }

    public synchronized void insertOpenApiSpec(
            String definition, String targetUrl, long sessionId, int contextId)
            throws DatabaseException {
        try {
            if (getConnection().isClosed()) {
                LOGGER.debug(
                        "Database connection is closed, skipping persisting the OpenAPI definition.");
                return;
            }
            psInsertOpenApiSpec.setClob(1, new JDBCClob(definition));
            psInsertOpenApiSpec.setString(2, targetUrl);
            psInsertOpenApiSpec.setLong(3, sessionId);
            psInsertOpenApiSpec.setInt(4, contextId);
            psInsertOpenApiSpec.execute();
        } catch (SQLException e) {
            String exceptionMessage = e.getMessage();
            if (exceptionMessage.contains("right truncation")
                    && exceptionMessage.contains("DEFINITION")) {
                LOGGER.warn(
                        "Could not persist the definition, {} is greater than the DEFINITION column limit.",
                        definition.length());
                return;
            }
            throw new DatabaseException(e);
        }
    }

    public synchronized List<TableOpenApiReadResult> getOpenApiDefinitionsForContext(int contextId)
            throws DatabaseException {
        try {
            psSelectOpenApiSpecsForContext.setInt(1, contextId);
            psSelectOpenApiSpecsForContext.execute();
            ResultSet rs = psSelectOpenApiSpecsForContext.getResultSet();
            List<TableOpenApiReadResult> results = new ArrayList<>();
            while (rs.next()) {
                results.add(
                        new TableOpenApiReadResult(
                                rs.getString("definition"),
                                rs.getString("target"),
                                rs.getLong("session_id"),
                                rs.getInt("context_id")));
            }
            return results;
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    public synchronized void deleteOpenApiSpecForContext(int contextId) throws DatabaseException {
        try {
            if (getConnection().isClosed()) {
                LOGGER.debug(
                        "Database connection is closed, skipping deleting the OpenAPI definition.");
                return;
            }
            psDeleteOpenApiSpecForContext.setInt(1, contextId);
            psDeleteOpenApiSpecForContext.execute();
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    static class TableOpenApiReadResult {
        public final String definition;
        public final String target;
        public final long sessionId;
        public final int contextId;

        public TableOpenApiReadResult(
                String definition, String target, long sessionId, int contextId) {
            this.definition = definition;
            this.target = target;
            this.sessionId = sessionId;
            this.contextId = contextId;
        }
    }
}
