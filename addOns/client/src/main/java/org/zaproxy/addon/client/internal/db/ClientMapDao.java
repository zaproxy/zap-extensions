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

import java.util.Map;
import java.util.function.Consumer;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import javax.jdo.Transaction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ClientSideDetails;

public class ClientMapDao {

    private static final Logger LOGGER = LogManager.getLogger(ClientMapDao.class);

    private ClientMapDao() {}

    public static long persistNode(ClientNode node) {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return -1;
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            ClientMapNode entry = toNode(node);
            pm.makePersistent(entry);
            tx.commit();
            return entry.getId();
        } catch (Exception e) {
            LOGGER.warn("Failed to persist client map node:", e);
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
        return -1;
    }

    public static long persistComponent(ClientNode node, ClientSideComponent component) {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return -1;
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            ClientMapComponent entry = toComponent(node, component);
            pm.makePersistent(entry);
            tx.commit();
            return entry.getId();
        } catch (Exception e) {
            LOGGER.warn("Failed to persist client map component:", e);
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
        return -1;
    }

    public static void forEachNode(Consumer<ClientMapNode> action) {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return;
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        try {
            Query<ClientMapNode> query = pm.newQuery(ClientMapNode.class);
            query.setOrdering("id ASC");
            query.executeList().forEach(action);
        } catch (Exception e) {
            LOGGER.error("An error occurred while iterating client map nodes:", e);
        } finally {
            pm.close();
        }
    }

    public static void forEachComponent(Consumer<ClientMapComponent> action) {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return;
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        try {
            Query<ClientMapComponent> query = pm.newQuery(ClientMapComponent.class);
            query.setOrdering("id ASC");
            query.executeList().forEach(action);
        } catch (Exception e) {
            LOGGER.error("An error occurred while iterating client map components:", e);
        } finally {
            pm.close();
        }
    }

    public static void deleteNodeById(long id) {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return;
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            Query<ClientMapNode> query = pm.newQuery(ClientMapNode.class, "id == :id");
            query.deletePersistentAll(id);
            tx.commit();
        } catch (Exception e) {
            LOGGER.warn("Failed to delete client map node with id {}:", id, e);
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }

    public static void updateNode(ClientNode node) {
        long id = node.getPersistenceId();
        if (id == -1) {
            return;
        }
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return;
        }
        PersistenceManager pm = pmf.getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            ClientMapNode entry = pm.getObjectById(ClientMapNode.class, id);
            ClientSideDetails details = node.getUserObject();
            entry.setContentLoaded(details.isContentLoaded());
            entry.setRedirect(details.isRedirect());
            entry.setVisited(details.isVisited());
            tx.commit();
        } catch (Exception e) {
            LOGGER.warn("Failed to update client map node:", e);
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }

    static ClientMapNode toNode(ClientNode from) {
        ClientSideDetails details = from.getUserObject();
        ClientMapNode entry = new ClientMapNode();
        entry.setUrl(details.getUrl());
        entry.setName(details.getName());
        entry.setVisited(details.isVisited());
        entry.setStorage(details.isStorage());
        entry.setContentLoaded(details.isContentLoaded());
        entry.setRedirect(details.isRedirect());
        return entry;
    }

    static ClientMapComponent toComponent(ClientNode node, ClientSideComponent component) {
        ClientMapComponent entry = new ClientMapComponent();
        entry.setNodeId(node.getPersistenceId());
        entry.setTagName(component.getTagName());
        entry.setElementId(component.getId());
        entry.setHref(component.getHref());
        entry.setText(component.getText());
        entry.setType(component.getType().getTypeKey());
        entry.setTagType(component.getTagType());
        int formId = component.getFormId();
        entry.setFormId(formId == -1 ? null : formId);
        return entry;
    }

    public static ClientSideComponent toComponent(ClientMapComponent entry, String nodeUrl) {
        int formId = entry.getFormId() != null ? entry.getFormId() : -1;
        ClientSideComponent comp =
                new ClientSideComponent(
                        Map.of(),
                        entry.getTagName() != null ? entry.getTagName() : "",
                        entry.getElementId(),
                        nodeUrl,
                        entry.getHref(),
                        entry.getText(),
                        ClientSideComponent.Type.getTypeForKey(entry.getType()),
                        entry.getTagType(),
                        formId);
        comp.setPersistenceId(entry.getId());
        return comp;
    }
}
