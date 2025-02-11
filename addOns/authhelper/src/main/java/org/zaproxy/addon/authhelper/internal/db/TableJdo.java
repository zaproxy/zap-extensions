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
package org.zaproxy.addon.authhelper.internal.db;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;
import javax.jdo.Constants;
import javax.jdo.JDOHelper;
import javax.jdo.PersistenceManagerFactory;
import org.datanucleus.PropertyNames;
import org.flywaydb.core.Flyway;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DatabaseServer;
import org.parosproxy.paros.db.DatabaseUnsupportedException;
import org.parosproxy.paros.db.paros.ParosAbstractTable;

public class TableJdo extends ParosAbstractTable {

    private static final String USER = "sa";

    private static PersistenceManagerFactory pmf;

    @Override
    public void databaseOpen(DatabaseServer server)
            throws DatabaseException, DatabaseUnsupportedException {
        if (pmf != null) {
            pmf.close();
            pmf = null;
        }

        super.databaseOpen(server);
    }

    @Override
    protected void reconnect(Connection conn) throws DatabaseException {
        try {
            String dbUrl = conn.getMetaData().getURL();
            ClassLoader classLoader = this.getClass().getClassLoader();
            Flyway.configure(classLoader)
                    .table("AUTHHELPER_FLYWAY_SCHEMA_HISTORY")
                    .baselineOnMigrate(true)
                    .baselineVersion("0")
                    .dataSource(dbUrl, USER, "")
                    .load()
                    .migrate();

            Properties jdoProperties = new Properties();
            jdoProperties.setProperty(Constants.PROPERTY_CONNECTION_URL, dbUrl);
            jdoProperties.setProperty(Constants.PROPERTY_CONNECTION_USER_NAME, USER);

            jdoProperties.put(PropertyNames.PROPERTY_CLASSLOADER_PRIMARY, classLoader);

            pmf = JDOHelper.getPersistenceManagerFactory(jdoProperties, "authhelper", classLoader);

        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    public static PersistenceManagerFactory getPmf() {
        return pmf;
    }
}
