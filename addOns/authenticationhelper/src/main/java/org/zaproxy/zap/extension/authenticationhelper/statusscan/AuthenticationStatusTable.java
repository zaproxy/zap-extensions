/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.authenticationhelper.statusscan;

import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusTableEntry.AuthenticationStatus;
import org.zaproxy.zap.view.table.HistoryReferencesTable;

/**
 * A {@link HistoryReferencesTable} with additional columns to graphically indicate authentication
 * status of individual messages and information on whether the provided logged in/out indicator
 * presents in the response message or not
 *
 * @see AuthenticationStatusTableModel
 * @see AuthenticationStatusTableEntry
 * @see AuthenticationStatus
 * @see AuthenticationStatusScanner.IndicatorStatus
 */
public class AuthenticationStatusTable extends HistoryReferencesTable {

    private static final long serialVersionUID = 8872957031673434524L;

    public static final String PANEL_NAME = "authenticationhelper.table";

    public AuthenticationStatusTable(AuthenticationStatusTableModel resultsModel) {
        super(resultsModel);

        setName("AuthenticationMessagesTable");
        setAutoCreateColumnsFromModel(false);

        getColumnExt(Constant.messages.getString("view.href.table.header.hrefid"))
                .setVisible(false);
        getColumnExt(Constant.messages.getString("view.href.table.header.timestamp.request"))
                .setVisible(false);
        getColumnExt(Constant.messages.getString("view.href.table.header.timestamp.response"))
                .setVisible(false);
        getColumnExt(Constant.messages.getString("view.href.table.header.size.requestheader"))
                .setVisible(false);
        getColumnExt(Constant.messages.getString("view.href.table.header.size.requestbody"))
                .setVisible(false);
        getColumnExt(Constant.messages.getString("view.href.table.header.tags")).setVisible(false);
        getColumnExt(Constant.messages.getString("view.href.table.header.highestalert"))
                .setVisible(false);

        getColumnExt(
                        Constant.messages.getString(
                                "authenticationhelper.table.authenticationStatus.header.status"))
                .setPreferredWidth(4);
        getColumnExt(
                        Constant.messages.getString(
                                "authenticationhelper.table.authenticationStatus.header.loggedInIndicator"))
                .setPreferredWidth(7);
        getColumnExt(
                        Constant.messages.getString(
                                "authenticationhelper.table.authenticationStatus.header.loggedOutIndicator"))
                .setPreferredWidth(7);
        getColumnExt(Constant.messages.getString("view.href.table.header.method"))
                .setPreferredWidth(5);
        getColumnExt(Constant.messages.getString("view.href.table.header.code"))
                .setPreferredWidth(5);

        setSortOrder(4, SortOrder.ASCENDING); // sort based on hrefid
    }
}
