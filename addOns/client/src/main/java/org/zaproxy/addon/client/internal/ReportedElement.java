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
package org.zaproxy.addon.client.internal;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import net.sf.json.JSONObject;

public class ReportedElement extends ReportedObject {

    private String tagType;
    private int formId = -1;
    private String role;
    private Map<String, String> ariaIdentification;

    public ReportedElement(JSONObject json) {
        super(json);
        this.tagType = getParam(json, "tagType");
        this.role = getParam(json, "role");
        if (json.containsKey("formId")) {
            this.formId = json.getInt("formId");
        }

        if (json.containsKey("ariaIdentification")
                && !json.get("ariaIdentification").equals(null)) {
            JSONObject ariaObj = json.getJSONObject("ariaIdentification");
            this.ariaIdentification = new HashMap<>();
            for (Object key : ariaObj.keySet()) {
                String keyStr = (String) key;
                this.ariaIdentification.put(keyStr, ariaObj.getString(keyStr));
            }
        }
    }

    public String getTagType() {
        return tagType;
    }

    public int getFormId() {
        return formId;
    }

    public String getRole() {
        return role;
    }

    public Map<String, String> getAriaIdentification() {
        return ariaIdentification != null ? Collections.unmodifiableMap(ariaIdentification) : null;
    }
}
