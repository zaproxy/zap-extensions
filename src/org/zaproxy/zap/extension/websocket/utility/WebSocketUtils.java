/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.utility;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.parosproxy.paros.extension.encoder.Encoder;

public final class WebSocketUtils {

    public static final String WEB_SOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private static Encoder encoder = new Encoder();

    public static String encodeWebSocketKey(String key) {
        String toEncode = key + WEB_SOCKET_GUID;

        try {
            return Base64.getEncoder().encodeToString(encoder.getHashSHA1(toEncode.getBytes()));
        } catch (NoSuchAlgorithmException e) {
            // Should never happen
            return null;
        }
    }

}
