/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2017 The ZAP Development Team
 *  
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.openapi.network;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FormData {

    private String type;
    private Map<String, FormDataItem> formItems;

    public FormData(List<String> consumes) {
        formItems = new HashMap<String, FormDataItem>();
        if (consumes != null && !consumes.isEmpty()) {
            if (consumes.contains("multipart/form-data")) {
                type = "multipart/form-data";
            } else {
                type = "application/x-www-form-urlencoded";
            }
        }
    }

    public void addFormItem(String name, FormDataItem value) {
        formItems.put(name, value);
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Map<String, FormDataItem> getFormItems() {
        return formItems;
    }

    public void setFormItems(Map<String, FormDataItem> formItems) {
        this.formItems = formItems;
    }

}
