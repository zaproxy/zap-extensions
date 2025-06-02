/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.paramdigger.gui;

import java.util.ArrayList;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.paramdigger.ParamGuessResult;

@SuppressWarnings("serial")
public class ParamDiggerOutputTableModel
        extends DefaultCustomColumnHistoryReferencesTableModel<ParamGuessResult> {

    private static final long serialVersionUID = 1L;

    public static final Column[] COLUMNS = {
        Column.HREF_ID,
        Column.METHOD,
        Column.URL,
        Column.STATUS_CODE,
        Column.STATUS_REASON,
        Column.RTT,
        Column.SIZE_MESSAGE,
        Column.CUSTOM,
    };

    private static final ArrayList<CustomColumn<ParamGuessResult>> CUSTOM_COLUMNS;

    static {
        CUSTOM_COLUMNS = new ArrayList<>();
        CUSTOM_COLUMNS.add(createResultColumn());
    }

    public ParamDiggerOutputTableModel() {
        super(COLUMNS, CUSTOM_COLUMNS, ParamGuessResult.class);
    }

    private static CustomColumn<ParamGuessResult> createResultColumn() {
        return new CustomColumn<ParamGuessResult>(
                String.class,
                Constant.messages.getString("paramdigger.output.table.result.column.name")) {

            @Override
            public Object getValue(ParamGuessResult result) {
                return result.toString();
            }
        };
    }
}
