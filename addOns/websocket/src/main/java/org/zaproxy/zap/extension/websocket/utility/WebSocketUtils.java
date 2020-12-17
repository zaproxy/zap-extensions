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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.websocket.WebSocketProtocol;

public final class WebSocketUtils {
    private static final Logger LOGGER = Logger.getLogger(WebSocketUtils.class);

    public static final String WEB_SOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    /** Given a Sec-WebSocket-Key, Generate response key Sec-WebSocket-Accept */
    public static String encodeWebSocketKey(String key) {
        String toEncode = key + WEB_SOCKET_GUID;

        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            sha.update(toEncode.getBytes());
            return Base64.getEncoder().encodeToString(sha.digest());
        } catch (NoSuchAlgorithmException e) {
            // Should never happen
            return null;
        }
    }

    /**
     * Generate a Sec-WebSocket-key which is used in handshake request
     *
     * @return new Sec-WebSocket-key
     */
    public static String generateSecWebSocketKey() {
        byte[] random = new byte[16];
        Random rand = new Random();
        rand.nextBytes(random);
        return Base64.getEncoder().encodeToString(random);
    }

    /**
     * Parses the negotiated WebSockets extensions. It splits them up into name and params of the
     * extension. In future we want to look up if given extension is available as ZAP extension and
     * then use their knowledge to process frames.
     *
     * <p>If multiple extensions are to be used, they can all be listed in a single {@link
     * WebSocketProtocol#HEADER_EXTENSION} field or split between multiple instances of the {@link
     * WebSocketProtocol#HEADER_EXTENSION} header field.
     *
     * @param msg
     * @return Map with extension name and parameter string.
     */
    public static Map<String, String> parseWebSocketExtensions(HttpMessage msg) {
        List<String> extensionHeaders =
                msg.getResponseHeader().getHeaderValues(WebSocketProtocol.HEADER_EXTENSION);

        if (extensionHeaders.isEmpty()) {
            return null;
        }

        /*
         * From http://tools.ietf.org/html/rfc6455#section-4.3:
         *   extension-list = 1#extension
         *   extension = extension-token *( ";" extension-param )
         *   extension-token = registered-token
         *   registered-token = token
         *   extension-param = token [ "=" (token | quoted-string) ]
         *    ; When using the quoted-string syntax variant, the value
         *    ; after quoted-string unescaping MUST conform to the
         *    ; 'token' ABNF.
         *
         * e.g.:  	Sec-WebSocket-Extensions: foo
         * 			Sec-WebSocket-Extensions: bar; baz=2
         *      is exactly equivalent to:
         * 			Sec-WebSocket-Extensions: foo, bar; baz=2
         *
         * e.g.:	Sec-WebSocket-Extensions: deflate-stream
         * 			Sec-WebSocket-Extensions: mux; max-channels=4; flow-control, deflate-stream
         * 			Sec-WebSocket-Extensions: private-extension
         */
        Map<String, String> wsExtensions = new LinkedHashMap<>();
        for (String extensionHeader : extensionHeaders) {
            for (String extension : extensionHeader.split(",")) {
                String key = extension.trim();
                String params = "";

                int paramsIndex = key.indexOf(";");
                if (paramsIndex != -1) {
                    key = extension.substring(0, paramsIndex).trim();
                    params = extension.substring(paramsIndex + 1).trim();
                }

                wsExtensions.put(key, params);
            }
        }
        /*
         * The interpretation of any extension parameters, and what constitutes
         * a valid response by a server to a requested set of parameters by a
         * client, will be defined by each such extension.
         *
         * Note that the order of extensions is significant!
         */

        return wsExtensions;
    }

    /**
     * Parses negotiated protocols out of the response header.
     *
     * <p>The {@link WebSocketProtocol#HEADER_PROTOCOL} header is only allowed to appear once in the
     * HTTP response (but several times in the HTTP request).
     *
     * <p>A server that speaks multiple sub-protocols has to make sure it selects one based on the
     * client's handshake and specifies it in its handshake.
     *
     * @param msg
     * @return Name of negotiated sub-protocol or null.
     */
    public static String parseWebSocketSubProtocol(HttpMessage msg) {
        String subProtocol = msg.getResponseHeader().getHeader(WebSocketProtocol.HEADER_PROTOCOL);
        return subProtocol;
    }

    /**
     * The {@link WebSocketProtocol#HEADER_VERSION} header might not always contain a number.
     * Therefore I return a string. Use the version to choose the appropriate processing class.
     *
     * @param msg
     * @return Version of the WebSockets channel, defining the protocol.
     */
    public static String parseWebSocketVersion(HttpMessage msg) {
        String version = msg.getResponseHeader().getHeader(WebSocketProtocol.HEADER_VERSION);

        if (version == null) {
            // check for requested WebSockets version
            version = msg.getRequestHeader().getHeader(WebSocketProtocol.HEADER_VERSION);

            if (version == null) {
                // default to version 13 if non is given, for whatever reason
                LOGGER.debug(
                        "No "
                                + WebSocketProtocol.HEADER_VERSION
                                + " header was provided - try version 13");
                version = "13";
            }
        }
        return version;
    }
}
