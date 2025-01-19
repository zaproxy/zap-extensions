/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.oast.internal;

import javax.jdo.JDOObjectNotFoundException;
import javax.jdo.Query;
import javax.jdo.Transaction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.database.PermanentDatabase;

public class OastPermanentDatabase extends PermanentDatabase {

    private static final Logger LOGGER = LogManager.getLogger(OastPermanentDatabase.class);

    public OastPermanentDatabase(String persistenceUnitName, ClassLoader classLoader) {
        super(persistenceUnitName, classLoader);
    }

    @SuppressWarnings("try")
    public AlertEntity getAlertForPayload(String payload) {
        try (var pm = getPm();
                Query<AlertEntity> query = pm.newQuery(AlertEntity.class)) {
            query.setFilter(":payload.indexOf(this.payload) != -1");
            var entity = query.setParameters(payload).executeUnique();

            if (entity == null) {
                return null;
            }

            pm.retrieve(entity);
            pm.retrieve(entity.getMessage());
            var copy = pm.detachCopy(entity);
            Transaction tx = pm.currentTransaction();
            try {
                tx.begin();
                pm.deletePersistent(entity);
                tx.commit();
            } finally {
                if (tx.isActive()) {
                    tx.rollback();
                }
            }
            return copy;
        } catch (JDOObjectNotFoundException e) {
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            LOGGER.error("An error occurred while getting the alert: ", e);
        }
        return null;
    }

    public void trim(int days) {
        if (days <= 0) {
            return;
        }
        LOGGER.debug("Trimming records older than {} days", days);
        try {
            // Yes, passing parameters in this way is horrible!
            // But I couldn't get the parameters working the "correct" way and we know its
            // definitely a positive int..
            String dateClause = "DATE_SUB(CURRENT_TIMESTAMP, INTERVAL " + days + " DAY)";

            Object res =
                    runQuery(
                            "DELETE FROM BOAST WHERE REGISTERED_TIMESTAMP < " + dateClause,
                            null,
                            false);
            if (Integer.parseInt(res.toString()) > 0) {
                LOGGER.info("Number of old BOAST records trimmed: {}", res);
            }

            res = runQuery("DELETE FROM ALERT WHERE CREATETIMESTAMP < " + dateClause, null, false);
            if (Integer.parseInt(res.toString()) > 0) {
                LOGGER.info("Number of old ALERT records trimmed: {}", res);
            }

            res =
                    runQuery(
                            "DELETE FROM MESSAGE WHERE CREATETIMESTAMP < " + dateClause,
                            null,
                            false);
            if (Integer.parseInt(res.toString()) > 0) {
                LOGGER.info("Number of old MESSAGE records trimmed: {}", res);
            }

        } catch (Exception e) {
            LOGGER.error("Failed to trim OAST permanent db", e);
        }
    }

    public void clearAllRecords() {
        try {
            Object res = runQuery("DELETE FROM BOAST", null, false);
            if (Integer.parseInt(res.toString()) > 0) {
                LOGGER.info("Number of old BOAST records trimmed: {}", res);
            }

            res = runQuery("DELETE FROM ALERT", null, false);
            if (Integer.parseInt(res.toString()) > 0) {
                LOGGER.info("Number of old ALERT records trimmed: {}", res);
            }

            res = runQuery("DELETE FROM MESSAGE", null, false);
            if (Integer.parseInt(res.toString()) > 0) {
                LOGGER.info("Number of old MESSAGE records trimmed: {}", res);
            }
        } catch (Exception e) {
            LOGGER.error("Failed to trim db", e);
        }
    }
}
