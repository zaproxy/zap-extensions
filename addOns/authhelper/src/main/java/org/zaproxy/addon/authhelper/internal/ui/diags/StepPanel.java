/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal.ui.diags;

import java.awt.BorderLayout;
import java.util.List;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.view.ZapTable;
import org.zaproxy.zap.view.table.DefaultHistoryReferencesTableEntry;
import org.zaproxy.zap.view.table.DefaultHistoryReferencesTableModel;
import org.zaproxy.zap.view.table.HistoryReferencesTable;
import org.zaproxy.zap.view.table.HistoryReferencesTableModel;

@SuppressWarnings("serial")
public class StepPanel extends JPanel {

    private static final Logger LOGGER = LogManager.getLogger(StepPanel.class);

    private static final HistoryReferencesTableModel.Column[] HREF_COLUMNS = {
        HistoryReferencesTableModel.Column.REQUEST_TIMESTAMP,
        HistoryReferencesTableModel.Column.METHOD,
        HistoryReferencesTableModel.Column.URL,
        HistoryReferencesTableModel.Column.STATUS_CODE,
        HistoryReferencesTableModel.Column.STATUS_REASON,
        HistoryReferencesTableModel.Column.RTT,
        HistoryReferencesTableModel.Column.SIZE_MESSAGE,
        HistoryReferencesTableModel.Column.SIZE_REQUEST_HEADER,
        HistoryReferencesTableModel.Column.SIZE_REQUEST_BODY,
        HistoryReferencesTableModel.Column.SIZE_RESPONSE_HEADER,
        HistoryReferencesTableModel.Column.SIZE_RESPONSE_BODY,
        HistoryReferencesTableModel.Column.TAGS,
    };

    StepPanel(String name, StepUi step) {
        setName(name);
        setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();

        if (!step.getMessagesIds().isEmpty()) {
            DefaultHistoryReferencesTableModel model =
                    new DefaultHistoryReferencesTableModel(HREF_COLUMNS);
            HistoryReferencesTable table = new HistoryReferencesTable(model);
            step.getMessagesIds()
                    .forEach(
                            id -> {
                                try {
                                    model.addEntry(
                                            new DefaultHistoryReferencesTableEntry(
                                                    new HistoryReference(id), HREF_COLUMNS));
                                } catch (HttpMalformedHeaderException | DatabaseException e) {
                                    LOGGER.warn(
                                            "An error occurred while reading the message with ID {}",
                                            id,
                                            e);
                                }
                            });
            tabbedPane.addTab(
                    Constant.messages.getString(
                            "authhelper.authdiags.panel.table.steps.tab.httpmessages",
                            step.getMessagesIds().size()),
                    new JScrollPane(table));
        }
        if (step.hasWebElement()) {
            ZapTable table = new ZapTable(new WebElementsTableModel(List.of(step.getWebElement())));
            tabbedPane.addTab(
                    Constant.messages.getString(
                            "authhelper.authdiags.panel.table.steps.tab.webelement"),
                    new JScrollPane(table));
        }
        if (!step.getWebElements().isEmpty()) {
            ZapTable table = new ZapTable(new WebElementsTableModel(step.getWebElements()));
            tabbedPane.addTab(
                    Constant.messages.getString(
                            "authhelper.authdiags.panel.table.steps.tab.webelements",
                            step.getWebElements().size()),
                    new JScrollPane(table));
        }

        if (!step.getBrowserStorageItems().isEmpty()) {
            ZapTable table =
                    new ZapTable(new BrowserStorageTableModel(step.getBrowserStorageItems()));

            tabbedPane.addTab(
                    Constant.messages.getString(
                            "authhelper.authdiags.panel.table.steps.tab.browserstorage",
                            step.getBrowserStorageItems().size()),
                    new JScrollPane(table));
        }

        add(tabbedPane);
    }
}
