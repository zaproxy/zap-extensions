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
package org.zaproxy.addon.network;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.network.internal.server.http.Alias;
import org.zaproxy.addon.network.internal.server.http.PassThrough;
import org.zaproxy.zap.common.VersionedAbstractParam;

/** The options related to local servers/proxies. */
public class LocalServersOptions extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(LocalServersOptions.class);
    /**
     * The current version of the configurations. Used to keep track of configuration changes
     * between releases, in case changes/updates are needed.
     *
     * <p>It only needs to be incremented for configuration changes (not releases of the add-on).
     *
     * @see #CONFIG_VERSION_KEY
     * @see #updateConfigsImpl(int)
     */
    private static final int CURRENT_CONFIG_VERSION = 1;

    private static final String BASE_KEY = "network.localServers";

    /**
     * The configuration key for the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = BASE_KEY + VERSION_ATTRIBUTE;

    private static final String ALIASES_BASE_KEY = BASE_KEY + ".aliases";
    private static final String ALL_ALIASES_KEY = ALIASES_BASE_KEY + ".alias";
    private static final String ALIAS_ENABLED = "enabled";
    private static final String ALIAS_NAME = "name";
    private static final String CONFIRM_REMOVE_ALIAS = ALIASES_BASE_KEY + ".confirmRemove";

    private static final String PASS_THROUGHS_BASE_KEY = BASE_KEY + ".passThroughs";
    private static final String ALL_PASS_THROUGHS_KEY = PASS_THROUGHS_BASE_KEY + ".passThrough";
    private static final String PASS_THROUGH_ENABLED = "enabled";
    private static final String PASS_THROUGH_AUTHORITY = "authority";
    private static final String CONFIRM_REMOVE_PASS_THROUGH =
            PASS_THROUGHS_BASE_KEY + ".confirmRemove";

    private List<Alias> aliases = new ArrayList<>();
    private boolean confirmRemoveAlias = true;
    private List<PassThrough> passThroughs = new ArrayList<>();
    private boolean confirmRemovePassThrough = true;

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // Nothing to do.
    }

    @Override
    protected void parseImpl() {
        List<HierarchicalConfiguration> fields =
                ((HierarchicalConfiguration) getConfig()).configurationsAt(ALL_ALIASES_KEY);
        aliases = new ArrayList<>(fields.size());
        for (HierarchicalConfiguration sub : fields) {
            try {
                String value = sub.getString(ALIAS_NAME, "");
                if (value != null && !value.isEmpty()) {
                    boolean enabled = sub.getBoolean(ALIAS_ENABLED, true);
                    aliases.add(new Alias(value, enabled));
                }
            } catch (ConversionException e) {
                LOGGER.warn("An error occurred while reading an alias:", e);
            }
        }
        confirmRemoveAlias = getBoolean(CONFIRM_REMOVE_ALIAS, true);

        fields = ((HierarchicalConfiguration) getConfig()).configurationsAt(ALL_PASS_THROUGHS_KEY);
        passThroughs = new ArrayList<>(fields.size());
        for (HierarchicalConfiguration sub : fields) {
            try {
                String value = sub.getString(PASS_THROUGH_AUTHORITY, "");
                Pattern pattern = createPassThroughPattern(value);
                if (pattern != null) {
                    boolean enabled = sub.getBoolean(PASS_THROUGH_ENABLED, true);
                    passThroughs.add(new PassThrough(pattern, enabled));
                }
            } catch (ConversionException e) {
                LOGGER.warn("An error occurred while reading a pass-through:", e);
            }
        }
        confirmRemovePassThrough = getBoolean(CONFIRM_REMOVE_PASS_THROUGH, true);
    }

    /**
     * Adds the given alias.
     *
     * @param alias the alias.
     * @throws NullPointerException if the given alias is {@code null}.
     */
    public void addAlias(Alias alias) {
        Objects.requireNonNull(alias);
        aliases.add(alias);
        persistAliases();
    }

    private void persistAliases() {
        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_ALIASES_KEY);

        for (int i = 0, size = aliases.size(); i < size; ++i) {
            String elementBaseKey = ALL_ALIASES_KEY + "(" + i + ").";
            Alias alias = aliases.get(i);

            getConfig().setProperty(elementBaseKey + ALIAS_NAME, alias.getName());
            getConfig().setProperty(elementBaseKey + ALIAS_ENABLED, alias.isEnabled());
        }
    }

    /**
     * Sets whether or not the alias with the given name should be enabled.
     *
     * @param name the name of the alias.
     * @param enabled {@code true} if the alias should be enabled, {@code false} otherwise.
     * @return {@code true} if the alias was changed, {@code false} otherwise.
     * @throws NullPointerException if the given name is {@code null}.
     */
    public boolean setAliasEnabled(String name, boolean enabled) {
        Objects.requireNonNull(name);
        for (Iterator<Alias> it = aliases.iterator(); it.hasNext(); ) {
            Alias alias = it.next();
            if (name.equals(alias.getName())) {
                alias.setEnabled(enabled);
                persistAliases();
                return true;
            }
        }
        return false;
    }

    /**
     * Removes an alias.
     *
     * @param name the name of the alias.
     * @return {@code true} if the alias was removed, {@code false} otherwise.
     */
    public boolean removeAlias(String name) {
        Objects.requireNonNull(name);
        for (Iterator<Alias> it = aliases.iterator(); it.hasNext(); ) {
            if (name.equals(it.next().getName())) {
                it.remove();
                persistAliases();
                return true;
            }
        }
        return false;
    }

    /**
     * Sets the aliases.
     *
     * @param aliases the aliases.
     * @throws NullPointerException if the given list is {@code null}.
     */
    public void setAliases(List<Alias> aliases) {
        Objects.requireNonNull(aliases);

        this.aliases = new ArrayList<>(aliases);
        persistAliases();
    }

    /**
     * Gets the aliases.
     *
     * @return the aliases, never {@code null}.
     */
    public List<Alias> getAliases() {
        return aliases;
    }

    /**
     * Sets whether or not the removal of an alias needs confirmation.
     *
     * @param confirmRemove {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public void setConfirmRemoveAlias(boolean confirmRemove) {
        this.confirmRemoveAlias = confirmRemove;
        getConfig().setProperty(CONFIRM_REMOVE_ALIAS, confirmRemoveAlias);
    }

    /**
     * Tells whether or not the removal of an alias needs confirmation.
     *
     * @return {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public boolean isConfirmRemoveAlias() {
        return confirmRemoveAlias;
    }

    /**
     * Adds the given pass-through.
     *
     * @param passThrough the pass-through.
     * @throws NullPointerException if the given pass-through is {@code null}.
     */
    public void addPassThrough(PassThrough passThrough) {
        Objects.requireNonNull(passThrough);
        passThroughs.add(passThrough);
        persistPassThroughs();
    }

    private void persistPassThroughs() {
        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_PASS_THROUGHS_KEY);

        for (int i = 0, size = passThroughs.size(); i < size; ++i) {
            String elementBaseKey = ALL_PASS_THROUGHS_KEY + "(" + i + ").";
            PassThrough passThrough = passThroughs.get(i);

            getConfig()
                    .setProperty(
                            elementBaseKey + PASS_THROUGH_AUTHORITY,
                            passThrough.getAuthority().pattern());
            getConfig().setProperty(elementBaseKey + PASS_THROUGH_ENABLED, passThrough.isEnabled());
        }
    }

    /**
     * Sets whether or not the pass-through with the given authority should be enabled.
     *
     * @param authority the value of the authority.
     * @param enabled {@code true} if the pass-through should be enabled, {@code false} otherwise.
     * @return {@code true} if the pass-through was changed, {@code false} otherwise.
     * @throws NullPointerException if the given authority is {@code null}.
     */
    public boolean setPassThroughEnabled(String authority, boolean enabled) {
        Objects.requireNonNull(authority);
        for (Iterator<PassThrough> it = passThroughs.iterator(); it.hasNext(); ) {
            PassThrough passThrough = it.next();
            if (authority.equals(passThrough.getAuthority().pattern())) {
                passThrough.setEnabled(enabled);
                persistPassThroughs();
                return true;
            }
        }
        return false;
    }

    /**
     * Removes a pass-through.
     *
     * @param authority the value of the authority.
     * @return {@code true} if the pass-through was removed, {@code false} otherwise.
     */
    public boolean removePassThrough(String authority) {
        Objects.requireNonNull(authority);
        for (Iterator<PassThrough> it = passThroughs.iterator(); it.hasNext(); ) {
            if (authority.equals(it.next().getAuthority().pattern())) {
                it.remove();
                persistPassThroughs();
                return true;
            }
        }
        return false;
    }

    /**
     * Sets the pass-through.
     *
     * @param passThroughs the pass-through.
     * @throws NullPointerException if the given list is {@code null}.
     */
    public void setPassThroughs(List<PassThrough> passThroughs) {
        this.passThroughs = Objects.requireNonNull(passThroughs);

        this.passThroughs = new ArrayList<>(passThroughs);
        persistPassThroughs();
    }

    /**
     * Gets all the pass-throughs.
     *
     * @return the list of pass-throughs, never {@code null}.
     */
    public List<PassThrough> getPassThroughs() {
        return passThroughs;
    }

    /**
     * Sets whether or not the removal of a pass-through needs confirmation.
     *
     * @param confirmRemove {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public void setConfirmRemovePassThrough(boolean confirmRemove) {
        this.confirmRemovePassThrough = confirmRemove;
        getConfig().setProperty(CONFIRM_REMOVE_PASS_THROUGH, confirmRemovePassThrough);
    }

    /**
     * Tells whether or not the removal of a pass-through needs confirmation.
     *
     * @return {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public boolean isConfirmRemovePassThrough() {
        return confirmRemovePassThrough;
    }

    private static Pattern createPassThroughPattern(String value) {
        try {
            return PassThrough.createAuthorityPattern(value);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Ignoring invalid pass-through pattern:", e);
            return null;
        }
    }
}
