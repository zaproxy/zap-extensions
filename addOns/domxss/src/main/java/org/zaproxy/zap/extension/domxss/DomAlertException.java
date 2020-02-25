/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.domxss;

public class DomAlertException extends Exception {

    private static final long serialVersionUID = 1L;
    private String url;
    private String attack;
    private String tagName;
    private String attributeId;
    private String attributeName;

    public DomAlertException(
            String url, String attack, String tagName, String attributeId, String attributeName) {
        super();
        this.url = url;
        this.attack = attack;
        this.tagName = tagName;
        this.attributeId = attributeId;
        this.attributeName = attributeName;
    }

    public DomAlertException(String url, String attack) {
        super();
        this.url = url;
        this.attack = attack;
    }

    public String getUrl() {
        return url;
    }

    public String getAttack() {
        return attack;
    }

    public static long getSerialversionuid() {
        return serialVersionUID;
    }

    public String getTagName() {
        return tagName;
    }

    public String getAttributeId() {
        return attributeId;
    }

    public String getAttributeName() {
        return attributeName;
    }
}
