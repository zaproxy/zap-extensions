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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.Getter;
import net.sf.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.client.ExtensionClientIntegration;

@Getter
@AllArgsConstructor
public class ClientSideComponent {

    public static String REDIRECT = "Redirect";

    private final Map<String, String> data;

    private String tagName;
    private String id;
    private String parentUrl;
    private String href;
    private String text;
    private String type;
    private String tagType;
    private int formId = -1;

    public ClientSideComponent(JSONObject json) {
        data = new HashMap<>();
        for (Object key : json.keySet()) {
            data.put(key.toString(), json.get(key).toString());
        }

        this.tagName = json.getString("tagName");
        this.id = json.getString("id");
        this.parentUrl = json.getString("url");
        this.type = json.getString("type");
        if (json.containsKey("href")) {
            this.href = json.getString("href");
        }
        if (json.containsKey("text")) {
            this.text = json.getString("text").trim();
        }
        if (json.containsKey("tagType")) {
            this.tagType = json.getString("tagType").trim();
        }
        if (json.containsKey("formId")) {
            this.formId = json.getInt("formId");
        }
    }

    public Map<String, String> getData() {
        return data;
    }

    public String getTypeForDisplay() {
        switch (tagName) {
            case "A":
                return Constant.messages.getString(
                        ExtensionClientIntegration.PREFIX + ".components.type.link");
            case "BUTTON":
                return Constant.messages.getString(
                        ExtensionClientIntegration.PREFIX + ".components.type.button");
            case "INPUT":
                return Constant.messages.getString(
                        ExtensionClientIntegration.PREFIX + ".components.type.input");
            default:
                String key = ExtensionClientIntegration.PREFIX + ".type." + type;
                if (tagName.isEmpty() && Constant.messages.containsKey(key)) {
                    return Constant.messages.getString(key);
                }
                return tagName;
        }
    }

    public boolean isStorageEvent() {
        if (type == null) {
            return false;
        }
        switch (type) {
            case "Cookies", "localStorage", "sessionStorage":
                return true;
            default:
                return false;
        }
    }

    @Override
    public int hashCode() {
        return Objects.hash(href, id, parentUrl, tagName, text);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        ClientSideComponent other = (ClientSideComponent) obj;
        return Objects.equals(href, other.href)
                && Objects.equals(id, other.id)
                && Objects.equals(parentUrl, other.parentUrl)
                && Objects.equals(tagName, other.tagName)
                && Objects.equals(text, other.text);
    }
}
