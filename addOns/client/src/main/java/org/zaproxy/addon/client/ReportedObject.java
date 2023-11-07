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

import java.util.Date;
import net.sf.json.JSONObject;
import org.parosproxy.paros.Constant;

public abstract class ReportedObject {

    private Date timestamp;
    private String type;
    private String tagName;
    private String id;
    private String nodeName;
    private String url;
    private String xpath;
    private String href;
    private String text;

    private static final String I18N_PREFIX = "client.type.";

    protected ReportedObject(JSONObject json) {
        this(json, json.getString("type"));
    }

    protected ReportedObject(JSONObject json, String type) {
        this.timestamp = new Date(json.getLong("timestamp"));
        this.type = type;
        this.tagName = getParam(json, "tagName");
        this.id = getParam(json, "id");
        this.nodeName = getParam(json, "nodeName");
        this.url = getParam(json, "url");
        this.xpath = getParam(json, "xpath");
        this.href = getParam(json, "href");
        this.text = getParam(json, "text");
    }

    protected static String getParam(JSONObject json, String param) {
        if (json.containsKey(param)) {
            return json.getString(param);
        }
        return null;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public String getType() {
        return type;
    }

    public String getI18nType() {
        if (Constant.messages.containsKey(I18N_PREFIX + type)) {
            return Constant.messages.getString(I18N_PREFIX + type);
        }
        return type;
    }

    public String getTagName() {
        return tagName;
    }

    public String getId() {
        return id;
    }

    public String getNodeName() {
        return nodeName;
    }

    public String getUrl() {
        return url;
    }

    public String getXpath() {
        return xpath;
    }

    public String getHref() {
        return href;
    }

    public String getText() {
        return text;
    }
}
