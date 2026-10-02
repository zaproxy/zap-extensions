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
package org.zaproxy.addon.authhelper.internal.db;

import javax.jdo.PersistenceManager;
import javax.jdo.Transaction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Shared JDO persist/delete logic for {@link Diagnostic}, used by full and policy-driven commits.
 */
public final class DiagnosticPersister {

    private static final Logger LOGGER = LogManager.getLogger(DiagnosticPersister.class);

    private DiagnosticPersister() {}

    /**
     * Persists the given diagnostic, populating its identity ({@link Diagnostic#getId()}) on
     * success.
     *
     * @param diagnostic the diagnostic to persist.
     * @param interruptedBefore whether the current thread was already known to be interrupted.
     * @return whether the current thread was (or became) interrupted during the call; the caller is
     *     responsible for restoring the interruption, JDO/DataNucleus does not.
     */
    public static boolean persist(Diagnostic diagnostic, boolean interruptedBefore) {
        boolean interrupted = interruptedBefore | Thread.interrupted();

        PersistenceManager pm = TableJdo.getPmf().getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            pm.makePersistent(diagnostic);
            tx.commit();
        } catch (Exception e) {
            LOGGER.warn("Failed to persist diagnostics:", e);
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
        return interrupted;
    }

    /**
     * Deletes the diagnostic with the given id, if it still exists.
     *
     * @param id the id of the diagnostic to delete.
     */
    public static void delete(int id) {
        PersistenceManager pm = TableJdo.getPmf().getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            Diagnostic diagnostic = pm.getObjectById(Diagnostic.class, id);
            pm.deletePersistent(diagnostic);
            tx.commit();
        } catch (Exception e) {
            LOGGER.warn("Failed to delete diagnostic {}:", id, e);
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }
}
