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
package org.zaproxy.addon.llm;

import java.awt.Window;
import java.util.Optional;

/**
 * UI for downloading a local model for a provider implemented outside the core LLM add-on (for
 * example Jlama / HuggingFace).
 */
public interface LlmLocalModelDownloadUi {

    /**
     * Returns the provider this download UI handles.
     *
     * @return the provider
     */
    LlmProvider getProvider();

    /**
     * Shows a modal download dialog.
     *
     * @param parent the parent window
     * @return the downloaded model id ({@code owner/name}), or empty if the user cancelled
     */
    Optional<String> showDownloadDialog(Window parent);
}
