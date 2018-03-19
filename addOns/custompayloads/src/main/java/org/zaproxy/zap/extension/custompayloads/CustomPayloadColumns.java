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
package org.zaproxy.zap.extension.custompayloads;

import java.util.ArrayList;
import java.util.List;

public final class CustomPayloadColumns {

    public static List<Column<CustomPayloadModel>> createColumns() {
        ArrayList<Column<CustomPayloadModel>> columns = new ArrayList<>();
        columns.add(createEnabledColumn());
        columns.add(createIdColumn());
        columns.add(createCategoryColumn());
        columns.add(createPayloadColumn());
        return columns;
    }

    public static List<Column<CustomPayloadModel>> createColumnsForOptionsTable() {
        ArrayList<Column<CustomPayloadModel>> columns = new ArrayList<>();
        columns.add(createEnabledColumn());
        columns.add(createIdColumn());
        columns.add(createCategoryColumn().AsReadonly());
        columns.add(createPayloadColumn().AsReadonly());
        return columns;
    }

    private static EditableColumn<CustomPayloadModel> createEnabledColumn() {
        return new EditableColumn<CustomPayloadModel>(
                Boolean.class, "custompayloads.options.dialog.enabled") {
            @Override
            public void setValue(CustomPayloadModel model, Object value) {
                model.setEnabled((Boolean) value);
            }

            @Override
            public Object getValue(CustomPayloadModel model) {
                return model.isEnabled();
            }
        };
    }

    private static Column<CustomPayloadModel> createIdColumn() {
        return new Column<CustomPayloadModel>(Integer.class, "custompayloads.options.dialog.id") {

            @Override
            public Object getValue(CustomPayloadModel model) {
                return model.getId();
            }
        };
    }

    private static EditableColumn<CustomPayloadModel> createPayloadColumn() {
        return new EditableColumn<CustomPayloadModel>(
                String.class, "custompayloads.options.dialog.payload") {
            @Override
            public void setValue(CustomPayloadModel model, Object value) {
                model.setPayload((String) value);
            }

            @Override
            public Object getValue(CustomPayloadModel model) {
                return model.getPayload();
            }
        };
    }

    private static EditableColumn<CustomPayloadModel> createCategoryColumn() {
        return new CustomPayloadCategoryColumn();
    }
}
