/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.zaproxy.zap.model.Context;

/**
 * The Manager that handles all the information related to {@link AlertFilter AlertFilters}
 * corresponding to a particular {@link Context}.
 */
public class ContextAlertFilterManager {

    /** The context id. */
    private int contextId;

    /** The model. */
    private List<AlertFilter> alertFilters;

    public ContextAlertFilterManager(int contextId) {
        this.contextId = contextId;
        this.alertFilters = new ArrayList<>();
    }

    /**
     * Builds a table model for the alertFilters.
     *
     * @return the model
     */
    public AlertFilterTableModel getAlertFiltersModel() {
        return new AlertFilterTableModel(this.alertFilters);
    }

    /**
     * Gets the context id to which this object corresponds.
     *
     * @return the context id
     */
    public int getContextId() {
        return contextId;
    }

    /**
     * Gets an unmodifiable view of the list of alertFilters.
     *
     * @return the alertFilters
     */
    public List<AlertFilter> getAlertFilters() {
        return Collections.unmodifiableList(alertFilters);
    }

    /**
     * Sets a new list of alertFilters for this context. An internal copy of the provided list is
     * stored.
     *
     * @param alertFilters the alertFilters
     * @return the list
     */
    public void setAlertFilters(List<AlertFilter> alertFilters) {
        this.alertFilters = new ArrayList<>(alertFilters);
    }

    /**
     * Adds an alertFilter.
     *
     * @param alertFilter the alertFilter being added
     */
    public void addAlertFilter(AlertFilter alertFilter) {
        alertFilters.add(alertFilter);
    }

    /**
     * Removes an alertFilter.
     *
     * @param alertFilter the alertFilter being removed
     */
    public boolean removeAlertFilter(AlertFilter alertFilter) {
        return alertFilters.remove(alertFilter);
    }

    /** Removes all the alertFilters. */
    public void removeAllAlertFilters() {
        this.alertFilters.clear();
    }
}
