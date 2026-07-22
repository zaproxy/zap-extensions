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
package org.zaproxy.addon.params.internal.db;

import java.util.ArrayList;
import java.util.List;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import javax.jdo.Transaction;

/** Persistence for tracked parameters in the Params add-on session table {@code PARAMS_PARAM}. */
public final class ParamsDao {

    private ParamsDao() {}

    @SuppressWarnings("unchecked")
    public static List<RecordParam> getAll(PersistenceManagerFactory pmf) {
        PersistenceManager pm = pmf.getPersistenceManager();
        Query<ParamsRow> query = pm.newQuery(ParamsRow.class);
        query.setOrdering("paramId ascending");
        try {
            List<ParamsRow> rows = (List<ParamsRow>) query.execute();
            List<RecordParam> result = new ArrayList<>(rows.size());
            for (ParamsRow row : rows) {
                result.add(toRecord(row));
            }
            return result;
        } finally {
            query.closeAll();
            pm.close();
        }
    }

    public static RecordParam insert(
            PersistenceManagerFactory pmf,
            String site,
            String type,
            String name,
            int used,
            String flags,
            String values) {
        ParamsRow row = new ParamsRow();
        row.setSite(site);
        row.setType(type);
        row.setName(name);
        row.setUsed(used);
        row.setFlags(flags);
        row.setVals(values);

        PersistenceManager pm = pmf.getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            pm.makePersistent(row);
            pm.flush();
            tx.commit();
            return toRecord(row);
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }

    public static void update(
            PersistenceManagerFactory pmf, long id, int used, String flags, String values) {
        PersistenceManager pm = pmf.getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            ParamsRow row = pm.getObjectById(ParamsRow.class, id);
            row.setUsed(used);
            row.setFlags(flags);
            row.setVals(values);
            tx.commit();
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }

    private static RecordParam toRecord(ParamsRow row) {
        return new RecordParam(
                row.getParamId(),
                row.getSite(),
                row.getType(),
                row.getName(),
                row.getUsed(),
                row.getFlags(),
                row.getVals());
    }
}
