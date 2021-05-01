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
package org.zaproxy.zap.extension.websocket.fuzz.processors;

import javax.script.ScriptException;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.fuzz.WebSocketFuzzerTaskProcessorUtils;

/**
 * An interface for scripts that process the messages of a WebSockets fuzzer.
 *
 * @see #TYPE_NAME
 * @see FuzzerWebSocketMessageScriptProcessorAdapter
 * @see WebSocketFuzzerTaskProcessorUtils
 */
public interface WebSocketFuzzerProcessorScript {

    /** The name used to identify the type of this script, for example, in configurations. */
    static final String TYPE_NAME = "websocketfuzzerprocessor";

    /**
     * Processes the fuzzed message before being forward to the server.
     *
     * @param utils utility class that contains methods that ease common tasks
     * @param message the fuzzed message that will be forward to the server
     * @throws ScriptException if an error occurs while executing the script
     */
    void processMessage(WebSocketFuzzerTaskProcessorUtils utils, WebSocketMessageDTO message)
            throws ScriptException;
}
