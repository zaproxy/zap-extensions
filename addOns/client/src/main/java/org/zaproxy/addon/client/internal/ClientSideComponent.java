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
import lombok.NonNull;
import net.sf.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.client.ExtensionClientIntegration;

@Getter
@AllArgsConstructor
public class ClientSideComponent implements Comparable<ClientSideComponent> {

    public static final String REDIRECT = "Redirect";
    public static final String CONTENT_LOADED = "ContentLoaded";

    public enum Type {
        LINK(
                "Link",
                Constant.messages.getString(
                        ExtensionClientIntegration.PREFIX + ".components.type.link"),
                "link"),
        BUTTON(
                "Button",
                Constant.messages.getString(
                        ExtensionClientIntegration.PREFIX + ".components.type.button"),
                "button"),
        INPUT(
                "Input",
                Constant.messages.getString(
                        ExtensionClientIntegration.PREFIX + ".components.type.input"),
                "input"),
        FORM(
                "Form",
                Constant.messages.getString(
                        ExtensionClientIntegration.PREFIX + ".components.type.form"),
                "form"),
        COOKIES(
                "Cookies",
                Constant.messages.getString(ExtensionClientIntegration.PREFIX + ".type.Cookies"),
                "Cookies"),
        LOCAL_STORAGE(
                "Local Storage",
                Constant.messages.getString(
                        ExtensionClientIntegration.PREFIX + ".type.localStorage"),
                "localStorage"),
        SESSION_STORAGE(
                "Session Storage",
                Constant.messages.getString(
                        ExtensionClientIntegration.PREFIX + ".type.sessionStorage"),
                "sessionStorage"),
        REDIRECT(
                "Redirect",
                Constant.messages.getString(
                        ExtensionClientIntegration.PREFIX + ".components.type.redirect"),
                "redirect"),
        CONTENT_LOADED(
                "Content Loaded",
                Constant.messages.getString(
                        ExtensionClientIntegration.PREFIX + ".components.type.contentLoaded"),
                "contentLoaded"),
        NODE_ADDED(
                "Node Added",
                Constant.messages.getString(ExtensionClientIntegration.PREFIX + ".type.nodeAdded"),
                "nodeAdded"),
        DOM_MUTATION(
                "DOM Mutation",
                Constant.messages.getString(
                        ExtensionClientIntegration.PREFIX + ".type.domMutation"),
                "domMutation"),
        PAGE_LOAD(
                "Page Load",
                Constant.messages.getString(ExtensionClientIntegration.PREFIX + ".type.pageLoad"),
                "pageLoad"),
        PAGE_UNLOAD(
                "Page Unload",
                Constant.messages.getString(ExtensionClientIntegration.PREFIX + ".type.pageUnload"),
                "pageUnload"),
        UNKNOWN(
                "Unknown",
                Constant.messages.getString("client.components.type.unknown"),
                "Unknown");

        private String label;
        private String name;
        private String typeKey;

        private Type(String label, String name, String typeKey) {
            this.label = label;
            this.name = name;
            this.typeKey = typeKey;
        }

        public String getLabel() {
            return label;
        }

        public String getName() {
            return name;
        }

        public String getTypeKey() {
            return typeKey;
        }

        public static Type getTypeForKey(String key) {
            for (Type type : Type.values()) {
                if (type.getTypeKey().equals(key)) {
                    return type;
                }
            }
            return Type.UNKNOWN;
        }
    }

    private final Map<String, String> data;

    private String tagName;
    private String id;
    private String parentUrl;
    private String href;
    private String text;
    @NonNull private Type type;
    private String tagType;
    private int formId = -1;

    public ClientSideComponent(JSONObject json) {
        data = new HashMap<>();
        for (Object key : json.keySet()) {
            String keyStr = key.toString();
            Object value = json.get(key);

            if ("ariaIdentification".equals(keyStr)) {
                if (value instanceof JSONObject) {
                    JSONObject ariaObj = (JSONObject) value;
                    Map<String, String> ariaMap = new HashMap<>();
                    for (Object ariaKey : ariaObj.keySet()) {
                        ariaMap.put(ariaKey.toString(), ariaObj.getString(ariaKey.toString()));
                    }
                    data.put("ariaIdentification", ariaMapToString(ariaMap));
                }
            } else {
                data.put(keyStr, value.toString());
            }
        }

        this.tagName = json.getString("tagName");
        this.id = json.getString("id");
        this.parentUrl = json.getString("url");
        this.type = Type.getTypeForKey(json.getString("type"));
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
                return Type.LINK.getName();
            case "BUTTON":
                return Type.BUTTON.getName();
            case "INPUT":
                return Type.INPUT.getName();
            default:
                if (type != null) {
                    String key = ExtensionClientIntegration.PREFIX + ".type." + type.getName();
                    if (tagName.isEmpty() && Constant.messages.containsKey(key)) {
                        return Constant.messages.getString(key);
                    }
                    key = ExtensionClientIntegration.PREFIX + ".type." + type.getTypeKey();
                    if (tagName.isEmpty() && Constant.messages.containsKey(key)) {
                        return Constant.messages.getString(key);
                    }
                }
                return tagName;
        }
    }

    public boolean isStorageEvent() {
        if (type == null) {
            return false;
        }
        switch (type) {
            case COOKIES, LOCAL_STORAGE, SESSION_STORAGE:
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

    @Override
    public int compareTo(ClientSideComponent other) {
        if (this.type == null || other.type == null) {
            return nullCompare(this.type, other.type);
        }
        int result = stringCompare(this.getType().getLabel(), other.getType().getLabel());
        if (result != 0) {
            return result;
        }
        result = stringCompare(this.href, other.href);
        if (result != 0) {
            return result;
        }
        result = stringCompare(this.text, other.text);
        if (result != 0) {
            return result;
        }
        result = stringCompare(this.id, other.id);
        if (result != 0) {
            return result;
        }
        result = stringCompare(this.tagName, other.tagName);
        if (result != 0) {
            return result;
        }
        result = stringCompare(this.tagType, other.tagType);
        if (result != 0) {
            return result;
        }
        result = Integer.compare(this.formId, other.formId);
        if (result != 0) {
            return result;
        }
        return 0;
    }

    private static int stringCompare(String here, String other) {
        if (here == null || other == null) {
            return nullCompare(here, other);
        }
        return here.compareTo(other);
    }

    private static int nullCompare(Object here, Object other) {
        if (here == other) {
            return 0;
        }
        if (here == null) {
            return -1;
        }
        return 1;
    }

    private static String ariaMapToString(Map<String, String> ariaMap) {
        JSONObject json = new JSONObject();
        for (Map.Entry<String, String> entry : ariaMap.entrySet()) {
            json.put(entry.getKey(), entry.getValue());
        }
        return json.toString();
    }
}
