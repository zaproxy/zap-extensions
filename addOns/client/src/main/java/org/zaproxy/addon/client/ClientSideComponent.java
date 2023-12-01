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
package org.zaproxy.addon.client;

import java.util.Objects;
import net.sf.json.JSONObject;
import org.parosproxy.paros.Constant;

public class ClientSideComponent {

    private String tagName;
    private String id;
    private String parentUrl;
    private String href;
    private String text;
    private String type;
    private String tagType;
    private int formId = -1;

    public ClientSideComponent(JSONObject json) {
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

    public String getTagName() {
        return tagName;
    }

    public String getId() {
        return id;
    }

    public String getParentUrl() {
        return parentUrl;
    }

    public String getHref() {
        return href;
    }

    public String getText() {
        return text;
    }

    public String getType() {
        return type;
    }

    public boolean isStorageEvent() {
        switch (type) {
            case "Cookies":
            case "localStorage":
            case "sessionStorage":
                return true;
            default:
                return false;
        }
    }

    public String getTagType() {
        return tagType;
    }

    public int getFormId() {
        return formId;
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
