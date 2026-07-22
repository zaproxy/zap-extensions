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

import java.util.List;
import java.util.Map;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.zap.control.AddOn;

/**
 * Represents a scan rule managed by the Global Scan Policy Manager.
 *
 * <p>Add-ons implement this interface (typically via an adapter wrapping their native rule type)
 * and register instances with {@link GspmRegistry}. GSPM then provides unified configuration and UI
 * across all rule types.
 *
 * @since 1.39.0
 */
public interface GspmRule {

    /** Returns the identifier for this rule, which must be unique across the registry. */
    int getId();

    /** Returns the human-readable name of this rule. */
    String getName();

    /**
     * Returns the key identifying the source tool for this rule.
     *
     * <p>Conventional values: {@code "ascan"}, {@code "pscan"}, {@code "client"}, {@code
     * "websockets"}, {@code "ptk"}.
     */
    String getTool();

    /**
     * Returns the category hierarchy for this rule as {@link GspmCategory} entries, from broadest
     * to most specific. Does not include the rule name itself. Must not be null or empty.
     */
    List<GspmCategory> getCategories();

    /**
     * Returns the alert tags associated with this rule, keyed by tag name.
     *
     * <p>May be empty but never {@code null}.
     */
    Map<String, String> getAlertTags();

    /** Returns {@code true} if this rule is currently enabled. */
    boolean isEnabled();

    /** Enables or disables this rule. */
    void setEnabled(boolean enabled);

    /**
     * Returns the alert threshold for this rule.
     *
     * <p>A threshold of {@link AlertThreshold#OFF} is equivalent to disabling the rule.
     */
    AlertThreshold getAlertThreshold();

    /** Sets the alert threshold for this rule. */
    void setAlertThreshold(AlertThreshold threshold);

    /**
     * Returns the attack strength for this rule, or {@code null} if the rule type does not support
     * attack strength (e.g. passive rules).
     */
    AttackStrength getAttackStrength();

    /**
     * Sets the attack strength for this rule.
     *
     * <p>Implementations that do not support attack strength should treat this as a no-op.
     */
    void setAttackStrength(AttackStrength strength);

    /** Returns the maturity status of this rule. Defaults to {@link AddOn.Status#unknown}. */
    default AddOn.Status getStatus() {
        return AddOn.Status.unknown;
    }

    /**
     * Returns the display name of the add-on that provides this rule, or {@code null} if unknown.
     */
    default String getAddOnName() {
        return null;
    }
}
