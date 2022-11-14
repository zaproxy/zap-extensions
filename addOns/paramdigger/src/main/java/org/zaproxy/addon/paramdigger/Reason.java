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
package org.zaproxy.addon.paramdigger;

public enum Reason {
    HTTP_CODE,
    HTTP_HEADERS,
    REDIRECT,
    BODY_HEURISTIC_MISMATCH,
    LINE_COUNT,
    WORD_COUNT,
    TEXT,
    PARAM_NAME_REFLECTION,
    PARAM_VALUE_REFLECTION,
    POISON_REFLECTION_IN_BODY,
    POISON_REFLECTION_IN_HEADER,
    POISON_REFLECTION_IN_COOKIE,
}
