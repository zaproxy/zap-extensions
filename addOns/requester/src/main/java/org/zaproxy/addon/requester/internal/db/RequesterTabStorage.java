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
package org.zaproxy.addon.requester.internal.db;

import java.sql.SQLException;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.requester.internal.exception.RequesterException;

/** Storage class that wraps table. */
@RequiredArgsConstructor
public class RequesterTabStorage {

    private static final Logger LOGGER = LogManager.getLogger(RequesterTabStorage.class);

    private final TableRequesterTab table;

    /**
     * Creates new tab and stores it in the database
     *
     * @param name Tab name (title)
     * @param index Tab index (order)
     * @param message Serialized message data
     * @return New tab record
     */
    public RequesterTabRecord createNewTab(
            String name, int index, JSONObject message, String messageType) {
        try {
            RequesterTabRecord tabRecord =
                    RequesterTabRecord.builder()
                            .id(UUID.randomUUID())
                            .name(name)
                            .index(index)
                            .message(message)
                            .messageType(messageType)
                            .build();
            table.insertTab(tabRecord);
            LOGGER.debug("Created tab with id {}.", tabRecord.getId());
            return tabRecord;
        } catch (SQLException e) {
            LOGGER.error("Could not create tab in database!", e);
            throw new RequesterException(e);
        }
    }

    /**
     * Obtains all tabs from database ordered by index
     *
     * @return List of ordered tabs
     */
    public List<RequesterTabRecord> getTabs() {
        try {
            List<RequesterTabRecord> tabs = table.getAllTabs();
            LOGGER.debug("Obtained {} request tabs.", tabs.size());
            return tabs;
        } catch (SQLException e) {
            LOGGER.error("Could not create tab in database!", e);
            throw new RequesterException(e);
        }
    }

    /**
     * Updates tab name in the database
     *
     * @param tabRecord Tab record to persist (only name will be saved)
     */
    public void updateTabName(RequesterTabRecord tabRecord) {
        try {
            table.updateTabName(tabRecord);
            LOGGER.debug("Updated tab name with id {}.", tabRecord.getId());
        } catch (SQLException e) {
            LOGGER.error("Could not update tab name in database!", e);
            throw new RequesterException(e);
        }
    }

    /**
     * Updates tab message in the database
     *
     * @param tabRecord Tab record to persist (only message will be saved)
     */
    public void updateTabMessage(RequesterTabRecord tabRecord) {
        try {
            table.updateTabMessage(tabRecord);
            LOGGER.debug("Updated tab message with id {}.", tabRecord.getId());
        } catch (SQLException e) {
            LOGGER.error("Could not update tab message in database!", e);
            throw new RequesterException(e);
        }
    }

    /**
     * Updates tab index in the database
     *
     * @param tabRecord Tab record to persist (only index will be saved)
     */
    public void updateTabIndex(RequesterTabRecord tabRecord) {
        try {
            table.updateTabIndex(tabRecord);
            LOGGER.debug("Updated tab index with id {}.", tabRecord.getId());
        } catch (SQLException e) {
            LOGGER.error("Could not update tab index in database!", e);
            throw new RequesterException(e);
        }
    }

    /**
     * Deletes tab record from the database
     *
     * @param tabRecord Tab record to delete
     */
    public void deleteTab(RequesterTabRecord tabRecord) {
        try {
            table.deleteTab(tabRecord);
            LOGGER.debug("Deleted tab with id {}.", tabRecord.getId());
        } catch (SQLException e) {
            LOGGER.error("Could not delete tab in database!", e);
            throw new RequesterException(e);
        }
    }
}
