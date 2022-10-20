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
package org.zaproxy.addon.database;

import java.io.Closeable;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import javax.jdo.Constants;
import javax.jdo.JDOHelper;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Transaction;
import org.datanucleus.PropertyNames;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.datanucleus.store.rdbms.RDBMSPropertyNames;
import org.flywaydb.core.Flyway;

public abstract class Database implements Closeable {

    private final PersistenceManagerFactory pmf;
    private final ClassLoader classLoader;

    protected Database(String persistenceUnitName, ClassLoader classLoader) {
        Properties jdoProperties = new Properties();
        jdoProperties.setProperty(
                Constants.PROPERTY_PERSISTENCE_MANAGER_FACTORY_CLASS,
                JDOPersistenceManagerFactory.class.getName());
        jdoProperties.setProperty(Constants.PROPERTY_CONNECTION_URL, getDbUrl());
        jdoProperties.setProperty(Constants.PROPERTY_CONNECTION_USER_NAME, getDbUsername());
        jdoProperties.setProperty(Constants.PROPERTY_CONNECTION_PASSWORD, getDbPass());
        jdoProperties.setProperty(Constants.PROPERTY_CONNECTION_DRIVER_NAME, getDbDriver());
        jdoProperties.setProperty(Constants.PROPERTY_MAPPING, getDbType());
        jdoProperties.setProperty(Constants.PROPERTY_PERSISTENCE_UNIT_NAME, persistenceUnitName);
        jdoProperties.put(PropertyNames.PROPERTY_CLASSLOADER_PRIMARY, classLoader);
        jdoProperties.put(PropertyNames.PROPERTY_DETACH_ALL_ON_COMMIT, Boolean.TRUE);

        // Optimizations based on
        // https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#performance_tuning
        jdoProperties.put(RDBMSPropertyNames.PROPERTY_CONNECTION_POOL_MAX_POOL_SIZE, 2);
        jdoProperties.put(RDBMSPropertyNames.PROPERTY_RDBMS_CHECK_EXISTS_TABLES_VIEWS, false);
        jdoProperties.put(RDBMSPropertyNames.PROPERTY_RDBMS_INIT_COLUMN_INFO, "NONE");
        jdoProperties.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_ALL, false);
        jdoProperties.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_TABLES, false);
        jdoProperties.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_COLUMNS, false);
        jdoProperties.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_CONSTRAINTS, false);
        jdoProperties.put(PropertyNames.PROPERTY_SCHEMA_VALIDATE_TABLES, false);
        jdoProperties.put(PropertyNames.PROPERTY_SCHEMA_VALIDATE_COLUMNS, false);
        jdoProperties.put(PropertyNames.PROPERTY_SCHEMA_VALIDATE_CONSTRAINTS, false);

        pmf = JDOHelper.getPersistenceManagerFactory(jdoProperties, classLoader);
        this.classLoader = classLoader;
    }

    @Override
    public void close() {
        if (pmf != null) {
            pmf.close();
        }
    }

    public void persistEntity(Object entity) {
        if (entity == null) {
            return;
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            pm.makePersistent(entity);
            tx.commit();
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }

    public <T> List<T> getAll(Class<T> clazz) {
        if (clazz == null) {
            throw new IllegalArgumentException("Class cannot be null.");
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            List<T> result = pm.newQuery(clazz).executeList();
            tx.commit();
            return result;
        } catch (Exception ignored) {
            return Collections.emptyList();
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }

    protected void migrate() {
        Flyway flyway =
                Flyway.configure(classLoader)
                        .dataSource(getDbUrl(), getDbUsername(), getDbPass())
                        .load();
        flyway.migrate();
    }

    protected abstract String getDbType();

    protected abstract String getDbDriver();

    protected abstract String getDbUrl();

    protected abstract String getDbUsername();

    protected abstract String getDbPass();
}
