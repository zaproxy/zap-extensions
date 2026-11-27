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
package org.zaproxy.addon.commonlib.gspm.internal;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.common.AbstractParam;

/**
 * The internal state of the Global Scan Policy Manager kept between ZAP sessions: the state of the
 * Policy tab of the active scan dialog, and whether the passive scan rules' settings were imported.
 *
 * <p>Not shown in the options nor exposed through the API.
 */
public class GspmParam extends AbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(GspmParam.class);

    private static final String BASE_KEY = "commonlib.gspm.ascanDialog";
    private static final String POLICY_KEY = BASE_KEY + ".policy";
    private static final String EDITED_KEY = BASE_KEY + ".edited";
    private static final String RULE_SETS_KEY = BASE_KEY + ".ruleSets";
    private static final String DEFAULT_POLICY_KEY = BASE_KEY + ".defaultPolicy";

    private static final String PASSIVE_IMPORTED_KEY = "commonlib.gspm.passiveImported";

    /**
     * The state of the Policy tab.
     *
     * @param policyName the name of the policy shown, or the one the edits started from.
     * @param edited {@code true} if the policy was edited.
     * @param ruleSets the rule sets of the edited policy, as JSON, {@code null} if not edited.
     * @param defaultPolicyName the name of the default policy when the state was saved, the state
     *     is not restored if the default policy changed since then, {@code null} if unknown.
     */
    public record State(
            String policyName, boolean edited, String ruleSets, String defaultPolicyName) {}

    private State state;

    private boolean passiveImported;

    @Override
    protected void parse() {
        passiveImported = getBoolean(PASSIVE_IMPORTED_KEY, false);
        String policyName = getString(POLICY_KEY, null);
        if (policyName == null || policyName.isBlank()) {
            state = null;
            return;
        }
        boolean edited = getBoolean(EDITED_KEY, false);
        state =
                new State(
                        policyName,
                        edited,
                        edited ? getString(RULE_SETS_KEY, null) : null,
                        getString(DEFAULT_POLICY_KEY, null));
    }

    /** Gets the saved state, {@code null} if none. */
    State getState() {
        return state;
    }

    /**
     * Sets and saves the state, if changed.
     *
     * @param state the state, must not be {@code null}.
     */
    void setState(State state) {
        if (state.equals(this.state)) {
            return;
        }
        this.state = state;
        getConfig().setProperty(POLICY_KEY, state.policyName());
        getConfig().setProperty(EDITED_KEY, state.edited());
        if (state.edited()) {
            getConfig().setProperty(RULE_SETS_KEY, state.ruleSets());
        } else {
            getConfig().clearProperty(RULE_SETS_KEY);
        }
        if (state.defaultPolicyName() != null) {
            getConfig().setProperty(DEFAULT_POLICY_KEY, state.defaultPolicyName());
        } else {
            getConfig().clearProperty(DEFAULT_POLICY_KEY);
        }
        save("the state of the active scan dialog's Policy tab");
    }

    /**
     * Tells whether or not the settings of the passive scan rules were already imported into the
     * default policy, done once, when the policies are first used for passive scanning.
     */
    boolean isPassiveImported() {
        return passiveImported;
    }

    /** Sets and saves that the settings of the passive scan rules were imported. */
    void setPassiveImported() {
        if (passiveImported) {
            return;
        }
        passiveImported = true;
        getConfig().setProperty(PASSIVE_IMPORTED_KEY, true);
        save("that the passive scan rules were imported");
    }

    private void save(String what) {
        try {
            getConfig().save();
        } catch (ConfigurationException e) {
            LOGGER.warn("Failed to save {}:", what, e);
        }
    }
}
