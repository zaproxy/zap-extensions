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
package org.zaproxy.zap.extension.fuzz.payloads.processor;

import javax.script.ScriptException;

/**
 * An interface for scripts that process the value of {@code DefaultPayload}s.
 *
 * @see #TYPE_NAME
 * @see org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload
 * @see ScriptStringPayloadProcessorAdapter
 */
public interface ScriptStringPayloadProcessor {

    /** The name used to identify the type of this script, for example, in configurations. */
    static final String TYPE_NAME = "payloadprocessor";

    /**
     * Returns the result of processing the given {@code payloadValue}.
     *
     * @param payloadValue the value of the payload that will be processed
     * @return the result of processing the value of the payload, never {@code null}.
     * @throws ScriptException if an error occurs while executing the script
     */
    String process(String payloadValue) throws ScriptException;
}
