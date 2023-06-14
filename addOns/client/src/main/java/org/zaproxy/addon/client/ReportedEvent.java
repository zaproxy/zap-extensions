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

public class ReportedEvent extends ReportedObject {

    private String tagName;
    private String url;
    private int count;

    public ReportedEvent(JSONObject json) {
        super(new Date(json.getLong("timestamp")), json.getString("eventName"));
        if (json.containsKey("tagName")) {
            this.tagName = json.getString("tagName");
        }
        this.url = json.getString("url");
        this.count = json.getInt("count");
    }

    public String getTagName() {
        return tagName;
    }

    public String getUrl() {
        return url;
    }

    public int getCount() {
        return count;
    }
}
