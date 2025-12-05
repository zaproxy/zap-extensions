/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound.alerts;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;

public abstract class FoxhoundBaseCheck implements FoxhoundVulnerabilityCheck {

    private static final Logger LOGGER = LogManager.getLogger(FoxhoundBaseCheck.class);

    protected abstract Vulnerability getVulnerability();

    protected abstract Set<String> getRequiredSourceNames();

    protected abstract Set<String> getRequiredSinkNames();

    @Override
    public String getVulnName() {
        return getVulnerability().getName();
    }

    @Override
    public String getDescription() {
        return getVulnerability().getDescription();
    }

    @Override
    public String getSolution() {
        return getVulnerability().getSolution();
    }

    @Override
    public String getReferences() {
        return getVulnerability().getReferencesAsString();
    }

    @Override
    public int getWascId() {
        return getVulnerability().getWascId();
    }

    @Override
    public boolean shouldAlert(TaintInfo taint) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    "Sinks: Need one of: {} got: {}",
                    getRequiredSinkNames(),
                    taint.getSink().getOperation());
            LOGGER.debug(
                    "Sources: Need one of: {} got: {}",
                    getRequiredSourceNames(),
                    taint.getSources().stream().map(TaintOperation::getOperation).toList());
        }

        if (!getRequiredSinkNames().contains(taint.getSink().getOperation())) {
            return false;
        }

        Set<String> sources = new HashSet<>();
        for (TaintOperation op : taint.getSources()) {
            sources.add(op.getOperation());
        }

        return !Collections.disjoint(sources, getRequiredSourceNames());
    }
}
