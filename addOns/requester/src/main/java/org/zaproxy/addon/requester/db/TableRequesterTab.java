/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.addon.requester.db;

import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.hsqldb.jdbc.JDBCClob;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DbUtils;
import org.parosproxy.paros.db.paros.ParosAbstractTable;

import java.sql.Clob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

/**
 * Table for persisting Requester tabs
 */
public class TableRequesterTab extends ParosAbstractTable {

    private static final String TABLE = "REQUESTER_TAB";

    private PreparedStatement psInsert;
    private PreparedStatement psSelect;
    private PreparedStatement psUpdateName;
    private PreparedStatement psUpdateMessage;
    private PreparedStatement psUpdateIndex;
    private PreparedStatement psDelete;

    @Override
    protected void reconnect(Connection connection) throws DatabaseException {
        try {
            if (!DbUtils.hasTable(connection, TABLE)) {
                DbUtils.execute(
                        connection,
                        "CREATE CACHED TABLE " + TABLE + " ("
                                + "id UUID NOT NULL, "
                                + "name NVARCHAR(256) NOT NULL, "
                                + "message CLOB(16M) NOT NULL, "
                                + "message_type NVARCHAR(256) NOT NULL, "
                                + "index INT NOT NULL, "
                                + "PRIMARY KEY (id))"
                );
            }

            psInsert = connection.prepareStatement(
                    "INSERT INTO "
                            + TABLE
                            + " (id,  name, message, message_type, index) "
                            + "VALUES (?, ?, ?, ?, ?)");

            psSelect = connection.prepareStatement(
                    "SELECT id, name, message, message_type, index FROM " + TABLE + " ORDER BY index");

            psUpdateName = connection.prepareStatement(
                    "UPDATE "
                            + TABLE
                            + " SET name = ? "
                            + " WHERE id = ?");

            psUpdateMessage = connection.prepareStatement(
                    "UPDATE "
                            + TABLE
                            + " SET message = ?, message_type = ? "
                            + " WHERE id = ?");

            psUpdateIndex = connection.prepareStatement(
                    "UPDATE "
                            + TABLE
                            + " SET index = ? "
                            + " WHERE id = ?");

            psDelete = connection.prepareStatement(
                    "DELETE FROM "
                            + TABLE
                            + " WHERE id = ?");
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /**
     * Inserts tab in the database
     * @param tabRecord Tab record to persist
     * @throws SQLException if there is an SQL error
     */
    public void insertTab(RequesterTabRecord tabRecord) throws SQLException {
        psInsert.setObject(1, tabRecord.getId());
        psInsert.setString(2, tabRecord.getName());
        psInsert.setClob(3, new JDBCClob(tabRecord.getMessage().toString()));
        psInsert.setString(4, tabRecord.getMessageType());
        psInsert.setInt(5, tabRecord.getIndex());

        psInsert.executeUpdate();
    }

    /**
     * Obtains all tabs from database ordered by index
     * @return List of ordered tabs
     * @throws SQLException if there is an SQL error
     */
    public List<RequesterTabRecord> getAllTabs() throws SQLException {
        List<RequesterTabRecord> tabRecords = new LinkedList<>();
        try (ResultSet resultSet = psSelect.executeQuery()) {
            while(resultSet.next()) {
                tabRecords.add(RequesterTabRecord.builder()
                        .id((UUID) resultSet.getObject(1))
                        .name(resultSet.getString(2))
                        .message(jsonObjectFromClob(resultSet.getClob(3)))
                        .messageType(resultSet.getString(4))
                        .index(resultSet.getInt(5))
                        .build());
            }
        }
        return tabRecords;
    }

    /**
     * Updates tab name in the database
     * @param tabRecord Tab record to persist (only name will be saved)
     * @throws SQLException if there is an SQL error
     */
    public void updateTabName(RequesterTabRecord tabRecord) throws SQLException {
        psUpdateName.setString(1, tabRecord.getName());
        psUpdateName.setObject(2, tabRecord.getId());

        psUpdateName.executeUpdate();
    }

    /**
     * Updates tab message in the database
     * @param tabRecord Tab record to persist (only message will be saved)
     * @throws SQLException if there is an SQL error
     */
    public void updateTabIndex(RequesterTabRecord tabRecord) throws SQLException {
        psUpdateIndex.setInt(1, tabRecord.getIndex());
        psUpdateIndex.setObject(2, tabRecord.getId());

        psUpdateIndex.executeUpdate();
    }

    /**
     * Updates tab index in the database
     * @param tabRecord Tab record to persist (only index will be saved)
     * @throws SQLException if there is an SQL error
     */
    public void updateTabMessage(RequesterTabRecord tabRecord) throws SQLException {
        psUpdateMessage.setClob(1, new JDBCClob(tabRecord.getMessage().toString()));
        psUpdateMessage.setString(2, tabRecord.getMessageType());
        psUpdateMessage.setObject(3, tabRecord.getId());

        psUpdateMessage.executeUpdate();
    }

    /**
     * Deletes tab record from the database
     * @param tabRecord Tab record to delete
     * @throws SQLException if there is an SQL error
     */
    public void deleteTab(RequesterTabRecord tabRecord) throws SQLException {
        psDelete.setObject(1, tabRecord.getId());

        psDelete.execute();
    }

    private JSONObject jsonObjectFromClob(Clob clob) throws SQLException {
        return (JSONObject) JSONSerializer.toJSON(clob.getSubString(1, (int) clob.length()));
    }

}
