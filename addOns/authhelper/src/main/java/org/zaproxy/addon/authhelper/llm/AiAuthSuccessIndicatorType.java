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

/**
 * How to determine that authentication is still valid when the generated Zest script is replayed.
 * The LLM provides this alongside a {@link AiAuthState#SUCCESS} response.
 */
public enum AiAuthSuccessIndicatorType {
    /** {@code value} is a substring or regex matched against the current URL after login. */
    URL_PATTERN,
    /**
     * {@code value} is a CSS selector; auth is valid when at least one matching element is visible.
     */
    ELEMENT_APPEARS,
    /**
     * {@code value} is a CSS selector; auth is valid when no matching element is visible (e.g.
     * login form is gone).
     */
    ELEMENT_DISAPPEARS
}
