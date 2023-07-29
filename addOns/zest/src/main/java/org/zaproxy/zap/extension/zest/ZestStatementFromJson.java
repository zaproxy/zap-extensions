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
import org.zaproxy.zest.core.v1.ZestClientElementClear;
import org.zaproxy.zest.core.v1.ZestClientElementClick;
import org.zaproxy.zest.core.v1.ZestClientElementSendKeys;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestClientSwitchToFrame;
import org.zaproxy.zest.core.v1.ZestClientWindowClose;
import org.zaproxy.zest.core.v1.ZestClientWindowResize;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestStatementFromJson {
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
    private static final String SLEEP_IN_SECONDS = "sleepInSeconds";
    private static final String FRAME_INDEX = "frameIndex";
    private static final String FRAME_NAME = "frameName";
    private static final String FRAME_ISPARENT = "parent";
    private static final String X_VALUE = "x";
    private static final String Y_VALUE = "y";

    private static final String ZEST_CLIENT_LAUNCH = "ZestClientLaunch";
    private static final String ZEST_CLIENT_ELEMENT_CLICK = "ZestClientElementClick";
    private static final String ZEST_CLIENT_ELEMENT_SEND_KEYS = "ZestClientElementSendKeys";
    private static final String ZEST_CLIENT_ELEMENT_CLEAR = "ZestClientElementClear";
    private static final String ZEST_CLIENT_WINDOW_CLOSE = "ZestClientWindowClose";
    private static final String ZEST_CLIENT_SWITCH_TO_FRAME = "ZestClientSwitchToFrame";
    private static final String ZEST_CLIENT_WINDOW_RESIZE = "ZestClientWindowResize";

    public static ZestStatement createZestStatementFromJson(JSONObject json) throws Exception {
        ZestStatement stmt = null;
        if (json.containsKey(ELEMENT_TYPE) && json.containsKey(INDEX)) {
            int index = json.getInt(INDEX);
            String elementType = json.getString(ELEMENT_TYPE);
            switch (elementType) {
                case ZEST_CLIENT_LAUNCH:
                    stmt =
                            (ZestStatement)
                                    new ZestClientLaunch(
                                            json.getString(WINDOW_HANDLE),
                                            json.getString(BROWSER_TYPE),
                                            json.getString(URL),
                                            json.getString(CAPABILITIES),
                                            json.getBoolean(HEADLESS));
                    break;

                case ZEST_CLIENT_ELEMENT_CLICK:
                    stmt =
                            (ZestStatement)
                                    new ZestClientElementClick(
                                            json.getString(WINDOW_HANDLE),
                                            json.getString(TYPE),
                                            json.getString(ELEMENT));
                    break;
                case ZEST_CLIENT_ELEMENT_SEND_KEYS:
                    stmt =
                            (ZestStatement)
                                    new ZestClientElementSendKeys(
                                            json.getString(WINDOW_HANDLE),
                                            json.getString(TYPE),
                                            json.getString(ELEMENT),
                                            json.getString(VALUE));
                    break;
                case ZEST_CLIENT_ELEMENT_CLEAR:
                    stmt =
                            (ZestStatement)
                                    new ZestClientElementClear(
                                            json.getString(WINDOW_HANDLE),
                                            json.getString(TYPE),
                                            json.getString(ELEMENT));
                    break;
                case ZEST_CLIENT_WINDOW_CLOSE:
                    stmt =
                            (ZestStatement)
                                    new ZestClientWindowClose(
                                            json.getString(WINDOW_HANDLE),
                                            json.getInt(SLEEP_IN_SECONDS));
                    break;
                case ZEST_CLIENT_SWITCH_TO_FRAME:
                    stmt =
                            (ZestStatement)
                                    new ZestClientSwitchToFrame(
                                            json.getString(WINDOW_HANDLE),
                                            json.getInt(FRAME_INDEX),
                                            json.getString(FRAME_NAME),
                                            json.getBoolean(FRAME_ISPARENT));
                    break;
                case ZEST_CLIENT_WINDOW_RESIZE:
                    stmt =
                            (ZestStatement)
                                    new ZestClientWindowResize(
                                            json.getString(WINDOW_HANDLE),
                                            json.getInt(X_VALUE),
                                            json.getInt(Y_VALUE));
                    break;
                default:
                    throw new Exception("Element Type Not found");
            }
        }
        return stmt;
    }
}
