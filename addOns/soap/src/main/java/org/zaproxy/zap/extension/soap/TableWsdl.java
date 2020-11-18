/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.soap;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import org.apache.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DbUtils;
import org.parosproxy.paros.db.paros.ParosAbstractTable;

/** Manages reading and writing SOAP Actions to the database. */
public class TableWsdl extends ParosAbstractTable {

    private static final Logger LOG = Logger.getLogger(TableWsdl.class);

    private PreparedStatement psInsertSoapAction;
    private PreparedStatement psSelectSourceSoapActions;
    private final Queue<SoapAction> soapActionBuffer = new LinkedList<>();

    /** Create tables if not already available */
    @Override
    protected void reconnect(Connection conn) throws DatabaseException {
        try {
            if (!DbUtils.hasTable(conn, "SOAP_WSDL")) {
                DbUtils.execute(
                        conn,
                        "CREATE CACHED TABLE soap_wsdl ("
                                + "wsdl_id INTEGER NOT NULL,"
                                + "soap_action NVARCHAR(4000) NOT NULL,"
                                + "PRIMARY KEY (wsdl_id, soap_action),"
                                + ")");
            }
            psInsertSoapAction =
                    conn.prepareStatement(
                            "MERGE INTO soap_wsdl AS s "
                                    + "USING (VALUES(?,?)) AS v(id,action) "
                                    + "ON s.wsdl_id = v.id AND s.soap_action = v.action "
                                    + "WHEN NOT MATCHED THEN INSERT VALUES v.id, v.action");
            psSelectSourceSoapActions =
                    conn.prepareStatement(
                            "SELECT wsdl_id, soap_action "
                                    + "FROM soap_wsdl "
                                    + "WHERE wsdl_id "
                                    + "IN ("
                                    + "SELECT wsdl_id "
                                    + "FROM soap_wsdl "
                                    + "WHERE soap_action = ?)");
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /**
     * Inserts a SOAP action into the database.
     *
     * @param soapAction the {@link SoapAction}
     */
    public synchronized void insertSoapAction(SoapAction soapAction) throws DatabaseException {
        try {
            if (getConnection().isClosed()) {
                // temporarily buffer actions and write them the next time
                soapActionBuffer.offer(soapAction);
                return;
            }

            do {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("insert SOAP action: " + soapAction.getAction());
                }

                psInsertSoapAction.setInt(1, soapAction.getWsdlId());
                psInsertSoapAction.setNString(2, soapAction.getAction());
                psInsertSoapAction.execute();

                soapAction = soapActionBuffer.poll();
            } while (soapAction != null);
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /**
     * Gets all the SOAP actions in the same WSDL document as the provided SOAP action.
     *
     * @param soapAction the SOAP Action
     * @return a {@link List} of {@link SoapAction}s available, never {@code null}.
     */
    public synchronized List<SoapAction> getSourceSoapActions(String soapAction)
            throws DatabaseException {
        try {
            psSelectSourceSoapActions.setNString(1, soapAction);
            psSelectSourceSoapActions.execute();
            ResultSet rsSoapActions = psSelectSourceSoapActions.getResultSet();
            List<SoapAction> soapActions = new ArrayList<>();
            while (rsSoapActions.next()) {
                soapActions.add(
                        new SoapAction(rsSoapActions.getInt(1), rsSoapActions.getNString(2)));
            }
            return soapActions;
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }
}
