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
package org.zaproxy.addon.commonlib.gspm;

/**
 * Implemented by add-ons (or commonlib itself) that want to contribute {@link GspmRule} instances
 * to the Global Scan Policy Manager registry.
 *
 * <p>Call {@link
 * org.zaproxy.addon.commonlib.ExtensionCommonlib#registerGspmRuleSource(GspmRuleSource)} to
 * register rules, and {@link
 * org.zaproxy.addon.commonlib.ExtensionCommonlib#unregisterGspmRuleSource(GspmRuleSource)} to
 * remove them on unload.
 *
 * @since 1.39.0
 */
public interface GspmRuleSource {

    /** Registers this source's rules with the given registry. */
    void registerRulesWithGspm(GspmRegistry registry);

    /** Unregisters this source's rules from the given registry. */
    void unregisterRulesFromGspm(GspmRegistry registry);
}
