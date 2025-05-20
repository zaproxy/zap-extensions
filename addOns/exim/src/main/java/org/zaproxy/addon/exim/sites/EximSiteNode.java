/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim.sites;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import org.parosproxy.paros.Constant;

public class EximSiteNode {

    public static final String ROOT_NODE_NAME = "Sites";
    public static final String NODE_KEY = "node";
    public static final String URL_KEY = "url";
    public static final String METHOD_KEY = "method";
    public static final String DATA_KEY = "data";
    public static final String RESPONSE_LENGTH_KEY = "responseLength";
    public static final String STATUS_CODE_KEY = "statusCode";
    public static final String CHILDREN_KEY = "children";

    private String node;
    private String url;
    private String method;
    private String data;
    private int responseLength;
    private int statusCode;
    private List<EximSiteNode> children = new ArrayList<>();
    private List<String> errors;

    private static final List<String> KEYS =
            Arrays.asList(
                    NODE_KEY,
                    URL_KEY,
                    METHOD_KEY,
                    DATA_KEY,
                    RESPONSE_LENGTH_KEY,
                    STATUS_CODE_KEY,
                    CHILDREN_KEY);

    public EximSiteNode() {}

    public EximSiteNode(LinkedHashMap<?, ?> lhm) {
        this(lhm, null);
    }

    private EximSiteNode(LinkedHashMap<?, ?> lhm, List<String> errors) {
        this.errors = errors;
        if (this.errors == null) {
            this.errors = new ArrayList<>();
        }

        node = getString(lhm, NODE_KEY);
        url = getString(lhm, URL_KEY);
        method = getString(lhm, METHOD_KEY);
        data = getString(lhm, DATA_KEY);
        responseLength = getInt(lhm, RESPONSE_LENGTH_KEY);
        statusCode = getInt(lhm, STATUS_CODE_KEY);

        Object childrenObj = lhm.get(CHILDREN_KEY);
        if (childrenObj != null) {
            if (childrenObj instanceof ArrayList) {
                ArrayList<?> al = (ArrayList<?>) childrenObj;
                al.forEach(
                        childObj -> {
                            if (childObj instanceof LinkedHashMap) {
                                children.add(
                                        new EximSiteNode(
                                                (LinkedHashMap<?, ?>) childObj, this.errors));
                            }
                        });
            }
        }
        lhm.keySet()
                .forEach(
                        key -> {
                            if (!KEYS.contains(key)) {
                                this.errors.add(
                                        Constant.messages.getString(
                                                "exim.sites.error.badkey", getName(), key));
                            }
                        });
    }

    private String getName() {
        String name = "";
        if (this.node != null) {
            name = this.node;
        } else if (this.url != null) {
            name = this.url;
        }
        return name;
    }

    private String getString(LinkedHashMap<?, ?> lhm, String key) {
        if (lhm.containsKey(key)) {
            Object obj = lhm.get(key);
            if (obj instanceof String) {
                return (String) obj;
            } else {
                this.errors.add(
                        Constant.messages.getString(
                                "exim.sites.error.badtype", getName(), key, obj));
            }
        }
        return null;
    }

    private int getInt(LinkedHashMap<?, ?> lhm, String key) {
        if (lhm.containsKey(key)) {
            Object obj = lhm.get(key);
            if (obj instanceof Integer) {
                return (Integer) obj;
            } else {
                this.errors.add(
                        Constant.messages.getString(
                                "exim.sites.error.badtype", getName(), key, obj));
            }
        }
        return -1;
    }

    public String getNode() {
        return node;
    }

    public void setNode(String node) {
        this.node = node;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public int getResponseLength() {
        return responseLength;
    }

    public void setResponseLength(int responseLength) {
        this.responseLength = responseLength;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public List<EximSiteNode> getChildren() {
        return children;
    }

    public void setChildren(List<EximSiteNode> children) {
        this.children = children;
    }

    public List<String> getErrors() {
        return errors;
    }
}
