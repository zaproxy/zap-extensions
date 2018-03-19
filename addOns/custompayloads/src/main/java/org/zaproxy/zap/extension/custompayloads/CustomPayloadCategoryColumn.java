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
import org.parosproxy.paros.control.Control;

public class CustomPayloadCategoryColumn extends EditableSelectColumn<CustomPayloadModel> {

    private ArrayList<String> defaultCategories;

    public CustomPayloadCategoryColumn() {
        super(String.class, "custompayloads.options.dialog.category");
    }

    @Override
    public void setValue(CustomPayloadModel model, Object value) {
        model.setCategory((String) value);
    }

    @Override
    public Object getValue(CustomPayloadModel model) {
        return model.getCategory();
    }

    @Override
    public ArrayList<Object> getSelectableValues(CustomPayloadModel model) {
        ArrayList<String> categories = getDefaultCategories();

        ArrayList<Object> categoryObjects = new ArrayList<>();
        boolean containsCategoryFromModel = false;
        for (String category : categories) {
            categoryObjects.add(category);
            if (category.equals(model.getCategory())) {
                containsCategoryFromModel = true;
            }
        }

        if (!containsCategoryFromModel
                && model.getCategory() != null
                && !model.getCategory().isEmpty()) {
            categoryObjects.add(model.getCategory());
        }

        return categoryObjects;
    }

    private ArrayList<String> getDefaultCategories() {
        if (defaultCategories == null) {
            defaultCategories = new ArrayList<>();
            for (CustomPayloadModel defaultModel : getExtension().getDefaultPayloads()) {
                if (!defaultCategories.contains(defaultModel.getCategory())) {
                    defaultCategories.add(defaultModel.getCategory());
                }
            }
        }
        return defaultCategories;
    }

    private ExtensionCustomPayloads getExtension() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionCustomPayloads.class);
    }
}
