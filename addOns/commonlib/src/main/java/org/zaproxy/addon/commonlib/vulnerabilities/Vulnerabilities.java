/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.vulnerabilities;

import java.util.List;
import org.zaproxy.addon.commonlib.internal.vulns.DefaultVulnerabilities;

/**
 * The vulnerabilities.
 *
 * @since 1.17.0
 */
public interface Vulnerabilities {

    /**
     * Gets the default vulnerabilities.
     *
     * <p>The vulnerabilities might be localized.
     *
     * @return the default vulnerabilities.
     */
    static Vulnerabilities getDefault() {
        return DefaultVulnerabilities.getInstance();
    }

    /**
     * Gets an unmodifiable {@code List} containing all the {@code Vulnerability}.
     *
     * @return the {@code List} containing all the {@code Vulnerability}, never {@code null}.
     */
    List<Vulnerability> getAll();

    /**
     * Gets the {@code Vulnerability} for the given ID, or {@code null} if not available.
     *
     * <p>The ID is in the form: {@code wasc_#ID}, e.g. {@code wasc_1}, {@code wasc_2}.
     *
     * @param id the ID of the vulnerability.
     * @return the {@code Vulnerability}, or {@code null} if not available.
     */
    Vulnerability get(String id);
}
