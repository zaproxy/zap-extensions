/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.oast.ui;

import java.util.ArrayList;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.oast.OastRequest;

public class OastTableModel extends DefaultCustomColumnHistoryReferencesTableModel<OastRequest> {

    private static final long serialVersionUID = 1L;
    public static final Column[] COLUMNS =
            new Column[] {
                Column.HREF_ID,
                Column.REQUEST_TIMESTAMP,
                Column.METHOD,
                Column.URL,
                Column.CUSTOM,
                Column.CUSTOM,
                Column.CUSTOM,
                Column.NOTE
            };

    private static final ArrayList<CustomColumn<OastRequest>> CUSTOM_COLUMNS;

    static {
        CUSTOM_COLUMNS = new ArrayList<>();
        CUSTOM_COLUMNS.add(createHandlerColumn());
        CUSTOM_COLUMNS.add(createSourceColumn());
        CUSTOM_COLUMNS.add(createRefererColumn());
    }

    public OastTableModel() {
        super(COLUMNS, CUSTOM_COLUMNS, OastRequest.class);
    }

    private static CustomColumn<OastRequest> createHandlerColumn() {
        return new CustomColumn<OastRequest>(
                String.class, Constant.messages.getString("oast.panel.table.column.handler")) {

            @Override
            public Object getValue(OastRequest model) {
                return model.getHandler();
            }
        };
    }

    private static CustomColumn<OastRequest> createSourceColumn() {
        return new CustomColumn<OastRequest>(
                String.class, Constant.messages.getString("oast.panel.table.column.source")) {

            @Override
            public Object getValue(OastRequest model) {
                return model.getSource();
            }
        };
    }

    private static CustomColumn<OastRequest> createRefererColumn() {
        return new CustomColumn<OastRequest>(
                String.class, Constant.messages.getString("oast.panel.table.column.referer")) {

            @Override
            public Object getValue(OastRequest model) {
                return model.getReferer();
            }
        };
    }
}
