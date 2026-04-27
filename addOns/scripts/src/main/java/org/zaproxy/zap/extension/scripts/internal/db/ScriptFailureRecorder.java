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

import java.time.Instant;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Transaction;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Persists script automation failures to the session database; failures never propagate to callers.
 */
public final class ScriptFailureRecorder {

    private static final Logger LOGGER = LogManager.getLogger(ScriptFailureRecorder.class);

    private static final int MAX_SCRIPT_NAME = 4096;
    private static final int MAX_SCRIPT_TYPE = 1024;
    private static final int MAX_MESSAGE = 8388608;

    private ScriptFailureRecorder() {}

    public static void record(String scriptName, String scriptType, String message) {
        if (StringUtils.isBlank(message)) {
            return;
        }
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return;
        }
        try {
            ScriptFailure entity = new ScriptFailure();
            entity.setCreateTimestamp(Instant.now());
            entity.setScriptName(truncate(scriptName, MAX_SCRIPT_NAME));
            entity.setScriptType(truncate(scriptType, MAX_SCRIPT_TYPE));
            entity.setMessage(truncate(message, MAX_MESSAGE));

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
        } catch (Exception e) {
            LOGGER.warn("Failed to persist script automation failure: {}", e.getMessage(), e);
        }
    }

    private static String truncate(String value, int maxChars) {
        if (value == null) {
            return "";
        }
        if (value.length() <= maxChars) {
            return value;
        }
        return value.substring(0, maxChars);
    }
}
