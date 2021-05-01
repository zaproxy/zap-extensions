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
package org.zaproxy.zap.extension.fuzz.payloads.generator;

import javax.script.ScriptException;

/**
 * An interface for scripts that generate {@code String}s payloads for use in a {@code
 * StringPayloadGenerator}.
 *
 * @see #TYPE_NAME
 * @see StringPayloadGenerator
 * @see ScriptStringPayloadGeneratorAdapter
 */
public interface ScriptStringPayloadGenerator {

    /** The name used to identify the type of this script, for example, in configurations. */
    static final String TYPE_NAME = "payloadgenerator";

    public long getNumberOfPayloads() throws ScriptException;

    boolean hasNext() throws ScriptException;

    String next() throws ScriptException;

    void reset() throws ScriptException;

    void close() throws ScriptException;
}
