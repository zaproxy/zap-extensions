/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.dev;

import java.util.Optional;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;

public class DevUtils {

    public static void setRedirect(HttpMessage msg, String url) {
        try {
            msg.setResponseHeader(new HttpResponseHeader("HTTP/1.1 302 Found"));
            msg.getResponseHeader().setHeader(HttpHeader.LOCATION, url);
            msg.getResponseHeader().setContentLength(0);
            msg.setResponseBody("");
        } catch (HttpMalformedHeaderException e) {
            // Should not happen
        }
    }

    public static String getUrlParam(HttpMessage msg, String param) {
        Optional<HtmlParameter> val =
                msg.getUrlParams().stream().filter(p -> p.getName().equals(param)).findAny();
        if (val.isPresent()) {
            return val.get().getValue();
        }
        return null;
    }

    public static String getFormParam(HttpMessage msg, String param) {
        Optional<HtmlParameter> val =
                msg.getFormParams().stream().filter(p -> p.getName().equals(param)).findAny();
        if (val.isPresent()) {
            return val.get().getValue();
        }
        return null;
    }
}
