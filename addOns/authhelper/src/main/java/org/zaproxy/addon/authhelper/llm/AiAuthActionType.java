/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.llm;

/** The type of browser action the LLM wants ZAP to perform. */
public enum AiAuthActionType {
    /** Click an element (button, link, etc.). No {@code value} is needed. */
    CLICK,
    /** Type text into an input field. {@code value} is the text to type. */
    SEND_KEYS,
    /**
     * Choose an option in a {@code <select>} element. {@code value} is the option text or value
     * attribute.
     */
    SELECT,
    /** Pause execution. {@code value} is the wait duration in seconds. */
    WAIT
}
