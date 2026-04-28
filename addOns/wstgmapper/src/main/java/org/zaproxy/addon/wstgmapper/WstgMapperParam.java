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
package org.zaproxy.addon.wstgmapper;

import java.io.File;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.wstgmapper.model.WstgTestStatus;
import org.zaproxy.zap.common.VersionedAbstractParam;

/**
 * Wraps the session-backed configuration used to persist checklist edits.
 *
 * <p>Status changes and tester notes flow through this class so the rest of the add-on can treat
 * persistence as a simple key-value service tied to the current ZAP session.
 */
public class WstgMapperParam extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(WstgMapperParam.class);

    private static final String BASE_KEY = "wstgmapper";
    private static final String TESTS_KEY = BASE_KEY + ".tests";
    private static final String CONFIG_VERSION_KEY = BASE_KEY + VERSION_ATTRIBUTE;

    protected static final int CURRENT_CONFIG_VERSION = 1;

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected void parseImpl() {}

    @Override
    protected void updateConfigsImpl(int fileVersion) {}

    public WstgTestStatus getStatus(String testId) {
        String raw = getString(TESTS_KEY + "." + testId + ".status", null);
        return raw == null ? WstgTestStatus.NOT_TESTED : WstgTestStatus.fromString(raw);
    }

    public void setStatus(String testId, WstgTestStatus status) {
        getConfig()
                .setProperty(
                        TESTS_KEY + "." + testId + ".status",
                        (status != null ? status : WstgTestStatus.NOT_TESTED).name());
        saveNow();
    }

    public String getNotes(String testId) {
        return getString(TESTS_KEY + "." + testId + ".notes", "");
    }

    public void setNotes(String testId, String notes) {
        getConfig().setProperty(TESTS_KEY + "." + testId + ".notes", notes != null ? notes : "");
        saveNow();
    }

    void bindToSessionFile(String sessionFileName) {
        if (getConfig() == null) {
            return;
        }

        File targetFile =
                ExtensionWstgMapper.hasPersistedSession(sessionFileName)
                        ? ExtensionWstgMapper.getWstgMapperSessionFile(sessionFileName)
                        : ExtensionWstgMapper.getUnsavedSessionFile();
        File currentFile = getConfig().getFile();
        if (targetFile.equals(currentFile)) {
            return;
        }

        targetFile.getParentFile().mkdirs();
        getConfig().setFile(targetFile);
    }

    public void saveNow() {
        bindToCurrentSessionFile();
        try {
            getConfig().save();
        } catch (ConfigurationException e) {
            LOGGER.debug(
                    "WSTG Mapper parameter save skipped (no backing file yet): {}", e.getMessage());
        }
    }

    private void bindToCurrentSessionFile() {
        try {
            Session session = Model.getSingleton().getSession();
            bindToSessionFile(session != null ? session.getFileName() : null);
        } catch (Exception e) {
            LOGGER.debug(
                    "WSTG Mapper parameter save skipped session rebinding: {}", e.getMessage());
        }
    }
}
