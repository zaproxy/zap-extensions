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
package org.zaproxy.zap.extension.zest;

import net.sf.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.zaproxy.zest.core.v1.ZestClientElementClick;
import org.zaproxy.zest.core.v1.ZestClientElementSendKeys;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestStatementFromJson {

    private ZestStatement stmt;
    private String elementType;
    private int index;

    private static final String type = "zestScript";
    private static final String I18N_PREFIX = "client.type.";
    private static final String ELEMENT_TYPE = "elementType";
    private static final String WINDOW_HANDLE = "windowHandle";
    private static final String BROWSER_TYPE = "browserType";
    private static final String HEADLESS = "headless";
    private static final String CAPABILITIES = "capabilities";
    private static final String URL = "url";
    private static final String INDEX = "index";
    private static final String TYPE = "type";
    private static final String ELEMENT = "element";
    private static final String VALUE = "value";

    private static final String ZEST_CLIENT_LAUNCH = "ZestClientLaunch";
    private static final String ZEST_CLIENT_ELEMENT_CLICK = "ZestClientElementClick";
    private static final String ZEST_CLIENT_ELEMENT_SEND_KEYS = "ZestClientElementSendKeys";

    protected ZestStatementFromJson(JSONObject json) throws Exception {
        super();
        if (json.containsKey(ELEMENT_TYPE) && json.containsKey(INDEX)) {
            index = json.getInt(INDEX);
            elementType = json.getString(ELEMENT_TYPE);
            switch (this.elementType) {
                case ZEST_CLIENT_LAUNCH:
                    this.stmt =
                            (ZestStatement)
                                    new ZestClientLaunch(
                                            json.getString(WINDOW_HANDLE),
                                            json.getString(BROWSER_TYPE),
                                            json.getString(URL),
                                            json.getString(CAPABILITIES),
                                            json.getBoolean(HEADLESS));
                    break;

                case ZEST_CLIENT_ELEMENT_CLICK:
                    this.stmt =
                            (ZestStatement)
                                    new ZestClientElementClick(
                                            json.getString(WINDOW_HANDLE),
                                            json.getString(TYPE),
                                            json.getString(ELEMENT));
                    break;
                case ZEST_CLIENT_ELEMENT_SEND_KEYS:
                    this.stmt =
                            (ZestStatement)
                                    new ZestClientElementSendKeys(
                                            json.getString(WINDOW_HANDLE),
                                            json.getString(TYPE),
                                            json.getString(ELEMENT),
                                            json.getString(VALUE));
                    break;
                default:
                    throw new Exception("Not found");
            }
        }
    }

    public ZestStatement getZestStatement() {
        return this.stmt;
    }

    public int getIndex() {
        return this.index;
    }

    public String getI18nType() {
        if (Constant.messages.containsKey(I18N_PREFIX + type)) {
            return Constant.messages.getString(I18N_PREFIX + type);
        }
        return type;
    }
}
