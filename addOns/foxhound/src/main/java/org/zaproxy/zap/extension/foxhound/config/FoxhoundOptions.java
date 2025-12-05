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
package org.zaproxy.zap.extension.foxhound.config;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class FoxhoundOptions extends VersionedAbstractParam {
    private static final Logger LOGGER = LogManager.getLogger(FoxhoundOptions.class);

    /** The base configuration key for all Foxhound configurations. */
    private static final String PARAM_BASE_KEY = "foxhound";

    private static final String PARAM_SERVER_PORT_KEY = PARAM_BASE_KEY + ".serverPort";
    private static final String SOURCES_DISABLED_KEY = PARAM_BASE_KEY + ".sourcesDisables";
    private static final String SINKS_DISABLED_KEY = PARAM_BASE_KEY + ".sinksDisabled";

    private PropertyChangeSupport pcs;

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int PARAM_CURRENT_VERSION = 1;

    // Default values
    public static final int DEFAULT_SERVER_PORT = 55676;

    // Concrete parameters
    private int serverPort = DEFAULT_SERVER_PORT;
    private List<String> sourcesDisabled;
    private List<String> sinksDisabled;

    public FoxhoundOptions() {
        this.pcs = new PropertyChangeSupport(this);
    }

    @Override
    protected String getConfigVersionKey() {
        return PARAM_BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return PARAM_CURRENT_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}

    private List<String> getStringList(String key) {
        List<String> items;
        try {
            items = getConfig().getList(key).stream().map(Object::toString).toList();
        } catch (Exception e) {
            LOGGER.warn(e.getMessage(), e);
            items = new ArrayList<>();
        }
        return items;
    }

    @Override
    protected void parseImpl() {
        serverPort = getConfig().getInt(PARAM_SERVER_PORT_KEY, DEFAULT_SERVER_PORT);
        sinksDisabled = getStringList(SINKS_DISABLED_KEY);
        sourcesDisabled = getStringList(SOURCES_DISABLED_KEY);
    }

    public int getServerPort() {
        return this.serverPort;
    }

    public void setServerPort(int serverPort) {
        int oldValue = this.serverPort;
        this.serverPort = serverPort;
        getConfig().setProperty(PARAM_SERVER_PORT_KEY, serverPort);
        pcs.firePropertyChange(PARAM_SERVER_PORT_KEY, oldValue, serverPort);
    }

    public List<String> getSourcesDisabled() {
        return sourcesDisabled;
    }

    public void setSourcesDisabled(List<String> disabled) {
        List<String> oldList = this.sourcesDisabled;
        this.sourcesDisabled = disabled;
        getConfig().setProperty(SOURCES_DISABLED_KEY, this.sourcesDisabled);
        pcs.firePropertyChange(SOURCES_DISABLED_KEY, oldList, this.sourcesDisabled);
    }

    public List<String> getSinksDisabled() {
        return sinksDisabled;
    }

    public void setSinkDisabled(List<String> disabled) {
        List<String> oldList = this.sinksDisabled;
        this.sinksDisabled = disabled;
        getConfig().setProperty(SINKS_DISABLED_KEY, this.sinksDisabled);
        pcs.firePropertyChange(SINKS_DISABLED_KEY, oldList, this.sinksDisabled);
    }

    public void addPropertyChangeListener(PropertyChangeListener listener) {
        pcs.addPropertyChangeListener(listener);
    }

    public void addPropertyChangeListener(String name, PropertyChangeListener listener) {
        pcs.addPropertyChangeListener(name, listener);
    }

    public void removePropertyChangeListener(PropertyChangeListener listener) {
        pcs.removePropertyChangeListener(listener);
    }

    public void removePropertyChangeListener(String name, PropertyChangeListener listener) {
        pcs.removePropertyChangeListener(name, listener);
    }
}
