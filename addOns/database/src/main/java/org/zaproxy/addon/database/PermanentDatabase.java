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

import java.nio.file.Paths;
import org.parosproxy.paros.Constant;

public class PermanentDatabase extends Database {

    private static final String PERMANENT_DB_TYPE = "hsql";
    private static final String PERMANENT_DB_DRIVER = "org.hsqldb.jdbcDriver";
    private static final String PERMANENT_DB_URL =
            "jdbc:hsqldb:file:"
                    + Paths.get(Constant.getZapHome(), "db", "permanent").toAbsolutePath();
    private static final String PERMANENT_DB_USERNAME = "sa";
    private static final String PERMANENT_DB_PASS = "";

    public PermanentDatabase(String persistenceUnitName, ClassLoader classLoader) {
        super(persistenceUnitName, classLoader);
        migrate();
    }

    @Override
    protected String getDbType() {
        return PERMANENT_DB_TYPE;
    }

    @Override
    protected String getDbDriver() {
        return PERMANENT_DB_DRIVER;
    }

    @Override
    protected String getDbUrl() {
        return PERMANENT_DB_URL;
    }

    @Override
    protected String getDbUsername() {
        return PERMANENT_DB_USERNAME;
    }

    @Override
    protected String getDbPass() {
        return PERMANENT_DB_PASS;
    }
}
