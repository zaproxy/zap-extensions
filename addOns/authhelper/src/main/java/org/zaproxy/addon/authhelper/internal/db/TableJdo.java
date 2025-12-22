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

import java.util.Properties;
import javax.jdo.Constants;
import javax.jdo.JDOHelper;
import javax.jdo.PersistenceManagerFactory;
import org.datanucleus.PropertyNames;
import org.datanucleus.store.rdbms.RDBMSPropertyNames;
import org.flywaydb.core.Flyway;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DatabaseListener;
import org.parosproxy.paros.db.DatabaseServer;

public class TableJdo implements DatabaseListener {

    private static PersistenceManagerFactory pmf;

    private final Database db;

    public TableJdo(Database db) throws DatabaseException {
        this.db = db;

        db.addDatabaseListener(this);
        databaseOpen(db.getDatabaseServer());
    }

    @Override
    public void databaseOpen(DatabaseServer db) throws DatabaseException {
        String dbUrl = db.getUrl();
        String user = db.getUser();
        String password = db.getPassword();
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
        jdoProperties.put(
                RDBMSPropertyNames.PROPERTY_RDBMS_STRING_LENGTH_EXCEEDED_ACTION, "TRUNCATE");

        pmf = JDOHelper.getPersistenceManagerFactory(jdoProperties, "authhelper", classLoader);
    }

    @Override
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
