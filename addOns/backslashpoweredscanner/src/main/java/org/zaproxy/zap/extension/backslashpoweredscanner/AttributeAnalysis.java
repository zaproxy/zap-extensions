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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.backslashpoweredscanner;

import java.util.HashMap;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpResponseHeader;

/*
 * AttributeAnalysis analyzes a bundle of HTTP response attribute (currently only headers, status cod, and content type)
 *
 */
public class AttributeAnalysis {
    private HashMap<String, Object> invariantAttributes;
    private HashMap<String, String> invariantHeaders;

    public AttributeAnalysis() {
        this.invariantAttributes = new HashMap<>();
        this.invariantHeaders = new HashMap<>();
    }

    public AttributeAnalysis(HttpResponseHeader header) {
        this.invariantHeaders = new HashMap<>();
        for (HttpHeaderField h : header.getHeaders()) {
            invariantHeaders.put(h.getName(), h.getValue());
        }
        this.invariantAttributes.put("headers", invariantHeaders);
        this.invariantAttributes.put("statuscode", header.getStatusCode());
        this.invariantAttributes.put("contenttype", getContentType(header));
    }

    public HashMap<String, Object> getInvariantAttributes() {
        return invariantAttributes;
    }

    public void analyzeInvariantAttributes(HttpResponseHeader header) {
        this.invariantHeaders = new HashMap<>();
        for (HttpHeaderField h : header.getHeaders()) {
            invariantHeaders.put(h.getName(), h.getValue());
        }
        this.invariantAttributes.put("headers", invariantHeaders);
        this.invariantAttributes.put("statuscode", header.getStatusCode());
        this.invariantAttributes.put("contenttype", getContentType(header));
    }

    public void updateWith(HttpResponseHeader header) {
        updateWith(new AttributeAnalysis(header).getInvariantAttributes());
    }

    public void updateWith(HashMap<String, Object> invariantAttributes) {
        HashMap<String, Object> newInvariantAttributes = new HashMap<>();
        for (String name : this.invariantAttributes.keySet()) {
            if (this.invariantAttributes.containsKey(name)
                    && this.invariantAttributes.get(name).equals(invariantAttributes.get(name))) {
                newInvariantAttributes.put(name, this.invariantAttributes.get(name));
            }
        }
        this.invariantAttributes = newInvariantAttributes;
    }

    public String getContentType(HttpResponseHeader header) {
        if (header.isHtml()) {
            return "Html";
        }
        if (header.isImage()) {
            return "Image";
        }
        if (header.isJavaScript()) {
            return "JavaScript";
        }
        if (header.isJson()) {
            return "Json";
        }
        if (header.isText()) {
            return "Text";
        }
        if (header.isXml()) {
            return "Xml";
        }
        return "Unknown";
    }
}
