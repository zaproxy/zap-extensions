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
package org.zaproxy.addon.retire;

import org.zaproxy.addon.retire.model.Repo;

/**
 * Interface for providing a {@link Repo} instance to the scan rule.
 *
 * <p>This allows dependency injection for testing and decouples the rule from the extension
 * implementation.
 */
public interface RepoHolder {

    /**
     * Returns the {@link Repo} instance.
     *
     * @return the repo instance, or {@code null} if not available
     */
    Repo getRepo();
}
