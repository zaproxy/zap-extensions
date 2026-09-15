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
package org.zaproxy.addon.authhelper;

/**
 * Implemented by AI-assisted authentication methods to expose the configuration setters the {@link
 * AuthTestDialog} needs without creating a direct compile-time dependency on the {@code
 * authhelper.llm} sub-extension package.
 */
public interface AiAssistedAuthTesterSupport {

    /** Unique method-type identifier for AI Assisted Authentication. */
    int METHOD_IDENTIFIER = 9;

    void setLoginPageUrl(String loginPageUrl);

    void setBrowserId(String browserId);

    void setLoginPageWait(int loginPageWait);

    /** Sets the free-text hint the LLM should use to navigate non-obvious UI steps. */
    void setHint(String hint);

    /**
     * Checks whether AI-assisted authentication is ready to run, e.g. that an LLM provider has been
     * configured.
     *
     * @return a human-readable reason it cannot run, or {@code null} if it's ready.
     */
    String checkPrerequisites();
}
