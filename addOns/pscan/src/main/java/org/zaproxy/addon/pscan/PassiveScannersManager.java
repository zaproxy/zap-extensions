/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.pscan;

import java.util.List;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * The manager of passive scanners.
 *
 * @since 0.1.0
 */
public interface PassiveScannersManager {

    /**
     * Adds the given scanner.
     *
     * <p>Scanners with duplicated name are not added.
     *
     * @param scanner the scanner to add.
     * @return {@code true} if the scanner was added, {@code false} otherwise.
     */
    boolean add(PassiveScanner scanner);

    /**
     * Removes the given scanner.
     *
     * @param scanner the scanner to remove.
     * @return {@code true} if the scanner was removed, {@code false} otherwise.
     */
    boolean remove(PassiveScanner scanner);

    /**
     * Gets all the scanners.
     *
     * @return the scanners, never {@code null}.
     */
    List<PassiveScanner> getScanners();

    /**
     * Gets the scan rule with the given ID.
     *
     * @param id the ID of the scan rule.
     * @return the scan rule, or {@code null} if not present.
     */
    PluginPassiveScanner getScanRule(int id);

    /**
     * Gets all the scan rules.
     *
     * @return the scan rules, never {@code null}.
     */
    List<PluginPassiveScanner> getScanRules();
}
