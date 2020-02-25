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

public abstract class EditableSelectColumn<T> extends EditableColumn<T> {

    public EditableSelectColumn(Class<?> columnClass, String name) {
        super(columnClass, name);
    }

    public abstract ArrayList<Object> getSelectableValues(T model);

    public <V> ArrayList<V> getTypedSelectableValues(T model) {
        ArrayList<Object> values = getSelectableValues(model);

        ArrayList<V> typedValues = new ArrayList<>();
        for (Object value : values) {
            V typedValue = getTypedObject(value);
            typedValues.add(typedValue);
        }

        return typedValues;
    }
}
