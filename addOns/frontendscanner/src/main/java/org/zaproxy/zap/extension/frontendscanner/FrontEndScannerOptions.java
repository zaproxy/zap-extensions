/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.frontendscanner;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import org.zaproxy.zap.common.VersionedAbstractParam;

/**
 * Manages the options saved in the configuration file.
 *
 * <p>It allows to change, programmatically, the following options:
 *
 * <ul>
 *   <li>Enabled state;
 * </ul>
 */
public class FrontEndScannerOptions extends VersionedAbstractParam {

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int PARAM_CURRENT_VERSION = 1;

    /** The base configuration key for all configurations. */
    private static final String PARAM_BASE_KEY = "frontendscanner";

    private static final String ENABLED_KEY = PARAM_BASE_KEY + ".enabled";

    private PropertyChangeSupport pcs;

    /**
     * Flag that indicates if the front-end scanner is enabled.
     *
     * <p>Default value is {@code false}.
     */
    private boolean enabled;

    public FrontEndScannerOptions() {
        this.pcs = new PropertyChangeSupport(this);
    }

    @Override
    protected int getCurrentVersion() {
        return PARAM_CURRENT_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return PARAM_BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // Nothing to update.
    }

    @Override
    protected void parseImpl() {
        enabled = getConfig().getBoolean(ENABLED_KEY, false);
    }

    /**
     * Tells whether or not the front-end scanner is enabled.
     *
     * @return {@code true} if the front-end scanner is enabled, {@code false} otherwise.
     * @see #setEnabled(boolean)
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether or not the front-end scanner is enabled.
     *
     * @param enabled {@code true} if the front-end scanner should be enabled, {@code false}
     *     otherwise.
     * @see #isEnabled()
     */
    public void setEnabled(boolean enabled) {
        if (this.enabled == enabled) {
            return;
        }

        this.enabled = enabled;
        getConfig().setProperty(ENABLED_KEY, enabled);
        pcs.firePropertyChange("enabled", !enabled, enabled);
    }

    void addPropertyChangeListener(PropertyChangeListener listener) {
        pcs.addPropertyChangeListener(listener);
    }

    void addPropertyChangeListener(String name, PropertyChangeListener listener) {
        pcs.addPropertyChangeListener(name, listener);
    }

    void removePropertyChangeListener(PropertyChangeListener listener) {
        pcs.removePropertyChangeListener(listener);
    }

    void removePropertyChangeListener(String name, PropertyChangeListener listener) {
        pcs.removePropertyChangeListener(name, listener);
    }
}
