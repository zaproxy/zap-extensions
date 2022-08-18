/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.soap;

import org.parosproxy.paros.network.HttpMessage;

public final class WsdlSpiderHelper {

    private WsdlSpiderHelper() {}

    public static boolean parseWsdl(WSDLCustomParser parser, HttpMessage message) {
        if (!canParseMessage(parser, message)) {
            return false;
        }

        String content = message.getResponseBody().toString().trim();
        parser.extContentWSDLImport(content, true);
        return true;
    }

    private static boolean canParseMessage(WSDLCustomParser parser, HttpMessage message) {
        if (canParseMessage(message)
                || message.getResponseHeader().hasContentType("text/xml", "application/wsdl+xml")) {
            String content = message.getResponseBody().toString();
            if (parser.canBeWSDLparsed(content)) {
                return true;
            }
        }
        return false;
    }

    public static boolean canParseMessage(HttpMessage message) {
        return message.getRequestHeader().getURI().toString().endsWith(".wsdl");
    }
}
