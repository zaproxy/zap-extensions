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

import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;
import javax.jdo.Constants;
import javax.jdo.JDOHelper;
import javax.jdo.PersistenceManagerFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.datanucleus.PropertyNames;
import org.flywaydb.core.Flyway;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DatabaseListener;
import org.parosproxy.paros.db.DatabaseServer;
import org.parosproxy.paros.db.paros.ParosDatabaseServer;

public class TableJdo implements DatabaseListener {

    private static final Logger LOGGER = LogManager.getLogger(TableJdo.class);

    private static Method getUrlMethod;
    private static Method getUserMethod;
    private static Method getPasswordMethod;

    private static PersistenceManagerFactory pmf;

    private final Database db;

    static {
        try {
            Class<?> dbServerClass = Class.forName("org.parosproxy.paros.db.DatabaseServer");
            getUrlMethod = dbServerClass.getMethod("getUrl");
            getUserMethod = dbServerClass.getMethod("getUser");
            getPasswordMethod = dbServerClass.getMethod("getPassword");

        } catch (Exception e) {
            LOGGER.debug("An error occurred while getting the methods:", e);
        }
    }

    public TableJdo(Database db) throws DatabaseException {
        this.db = db;

        db.addDatabaseListener(this);
        databaseOpen(db.getDatabaseServer());
    }

    @Override
    public void databaseOpen(DatabaseServer db) throws DatabaseException {
        if (getUrlMethod == null) {
            closing(db);
        }

        String dbUrl = getUrl(db);
        String user = getUser(db);
        String password = getPassword(db);
        ClassLoader classLoader = this.getClass().getClassLoader();
        Flyway.configure(classLoader)
                .table("AUTHHELPER_FLYWAY_SCHEMA_HISTORY")
                .baselineOnMigrate(true)
                .baselineVersion("0")
                .dataSource(dbUrl, user, password)
                .load()
                .migrate();

        Properties jdoProperties = new Properties();
        jdoProperties.setProperty(Constants.PROPERTY_CONNECTION_URL, dbUrl);
        jdoProperties.setProperty(Constants.PROPERTY_CONNECTION_USER_NAME, user);
        jdoProperties.setProperty(Constants.PROPERTY_CONNECTION_PASSWORD, password);

        jdoProperties.put(PropertyNames.PROPERTY_CLASSLOADER_PRIMARY, classLoader);

        pmf = JDOHelper.getPersistenceManagerFactory(jdoProperties, "authhelper", classLoader);
    }

    private static String getUrl(DatabaseServer db) throws DatabaseException {
        try {
            if (getUrlMethod != null) {
                return (String) getUrlMethod.invoke(db);
            }
        } catch (Exception e) {
            LOGGER.warn("An error occurred while getting the URL:", e);
        }

        try (Connection connection = getConnection(db)) {
            return connection.getMetaData().getURL();
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    private static Connection getConnection(DatabaseServer db) throws SQLException {
        if (db instanceof ParosDatabaseServer pds) {
            return pds.getNewConnection();
        }
        if (db instanceof ParosDatabaseServer pds) {
            return pds.getNewConnection();
        }
        throw new SQLException("Unknown DB implementation");
    }

    private static String getUser(DatabaseServer db) {
        try {
            if (getUserMethod != null) {
                return (String) getUserMethod.invoke(db);
            }
        } catch (Exception e) {
            LOGGER.warn("An error occurred while getting the user:", e);
        }

        return "sa";
    }

    private static String getPassword(DatabaseServer db) {
        try {
            if (getPasswordMethod != null) {
                return (String) getPasswordMethod.invoke(db);
            }
        } catch (Exception e) {
            LOGGER.warn("An error occurred while getting the password:", e);
        }

        return "";
    }

    // @Override
    public void closing(DatabaseServer db) {
        if (pmf != null) {
            pmf.close();
            pmf = null;
        }
    }

    public void unload() {
        db.removeDatabaseListener(this);
    }

    public static PersistenceManagerFactory getPmf() {
        return pmf;
    }
}
