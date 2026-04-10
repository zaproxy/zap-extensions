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
package org.zaproxy.addon.client.internal.db;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import javax.jdo.Transaction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.client.internal.ReportedElement;
import org.zaproxy.addon.client.internal.ReportedEvent;
import org.zaproxy.addon.client.internal.ReportedObject;

public class ClientHistoryDao {

    private static final Logger LOGGER = LogManager.getLogger(ClientHistoryDao.class);

    private static final int OBJECT_TYPE_ELEMENT = 1;
    private static final int OBJECT_TYPE_EVENT = 2;

    private ClientHistoryDao() {}

    public static void persist(ReportedObject obj) {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return;
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            pm.makePersistent(toEntry(obj));
            tx.commit();
        } catch (Exception e) {
            LOGGER.warn("Failed to persist client history entry:", e);
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }

    public static List<ReportedObject> loadAll() {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return List.of();
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        try {
            Query<ClientHistoryEntry> query = pm.newQuery(ClientHistoryEntry.class);
            query.setOrdering("id ASC");
            List<ClientHistoryEntry> entries = query.executeList();
            List<ReportedObject> result = new ArrayList<>(entries.size());
            for (ClientHistoryEntry entry : entries) {
                result.add(toReportedObject(entry));
            }
            return result;
        } catch (Exception e) {
            LOGGER.error("An error occurred while loading client history:", e);
            return List.of();
        } finally {
            pm.close();
        }
    }

    public static void deleteAll() {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return;
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            pm.newQuery(ClientHistoryEntry.class).deletePersistentAll();
            tx.commit();
        } catch (Exception e) {
            LOGGER.warn("Failed to delete client history entries:", e);
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }

    static ClientHistoryEntry toEntry(ReportedObject obj) {
        ClientHistoryEntry entry = new ClientHistoryEntry();
        entry.setTimestamp(obj.getTimestamp().toInstant());
        entry.setType(obj.getType());
        entry.setTagName(obj.getTagName());
        entry.setElementId(obj.getId());
        entry.setNodeName(obj.getNodeName());
        entry.setUrl(obj.getUrl());
        entry.setXpath(obj.getXpath());
        entry.setHref(obj.getHref());
        entry.setText(obj.getText());

        if (obj instanceof ReportedElement element) {
            entry.setObjectType(OBJECT_TYPE_ELEMENT);
            entry.setTagType(element.getTagType());
            entry.setFormId(element.getFormId());
        } else if (obj instanceof ReportedEvent event) {
            entry.setObjectType(OBJECT_TYPE_EVENT);
            entry.setCount(event.getCount());
        }
        return entry;
    }

    static ReportedObject toReportedObject(ClientHistoryEntry entry) {
        if (OBJECT_TYPE_EVENT == entry.getObjectType()) {
            return new ReportedEvent(
                    new Date(entry.getTimestamp().toEpochMilli()),
                    entry.getType(),
                    entry.getTagName(),
                    entry.getElementId(),
                    entry.getNodeName(),
                    entry.getUrl(),
                    entry.getXpath(),
                    entry.getHref(),
                    entry.getText(),
                    entry.getCount() != null ? entry.getCount() : 0);
        }
        return new ReportedElement(
                new Date(entry.getTimestamp().toEpochMilli()),
                entry.getType(),
                entry.getTagName(),
                entry.getElementId(),
                entry.getNodeName(),
                entry.getUrl(),
                entry.getXpath(),
                entry.getHref(),
                entry.getText(),
                entry.getTagType(),
                entry.getFormId() != null ? entry.getFormId() : -1);
    }
}
