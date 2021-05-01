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

public abstract class Column<T> {
    Class<?> columnClass;
    String nameKey;

    public Column(Class<?> columnClass, String nameKey) {
        this.columnClass = columnClass;
        this.nameKey = nameKey;
    }

    public Class<?> getColumnClass() {
        return columnClass;
    }

    public String getNameKey() {
        return nameKey;
    }

    public boolean isEditable(T model) {
        return false;
    }

    public abstract Object getValue(T model);

    public <V> V getTypedValue(T model) {
        Object value = getValue(model);
        return getTypedObject(value);
    }

    @SuppressWarnings("unchecked")
    protected <V> V getTypedObject(Object value) {
        if (value == null) {
            return null;
        }

        Class<?> type = getColumnClass();
        if (value.getClass() != type) {
            return null;
        }
        return (V) value;
    }
}
