/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts.internal.db;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.scripts.report.ScriptAutomationFailureRow;

/** Read-only access to {@link ScriptFailure} rows for reporting. */
public final class ScriptFailureReportQuery {

    private static final Logger LOGGER = LogManager.getLogger(ScriptFailureReportQuery.class);

    private ScriptFailureReportQuery() {}

    public static List<ScriptAutomationFailureRow> loadAllForReport() {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return List.of();
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        try {
            Query<ScriptFailure> query = pm.newQuery(ScriptFailure.class);
            query.setOrdering("id ascending");
            @SuppressWarnings("unchecked")
            Collection<ScriptFailure> entities = (Collection<ScriptFailure>) query.execute();
            List<ScriptAutomationFailureRow> rows = new ArrayList<>();
            for (ScriptFailure entity : entities) {
                rows.add(
                        new ScriptAutomationFailureRow(
                                entity.getScriptName(),
                                entity.getScriptType(),
                                entity.getMessage(),
                                entity.getCreateTimestamp() != null
                                        ? entity.getCreateTimestamp().toString()
                                        : ""));
            }
            return rows;
        } catch (Exception e) {
            LOGGER.warn("Failed to load script automation failures for report: {}", e.getMessage());
            return List.of();
        } finally {
            pm.close();
        }
    }
}
