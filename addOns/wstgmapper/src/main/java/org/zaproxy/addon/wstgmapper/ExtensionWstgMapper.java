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
import java.io.IOException;
import java.nio.file.Files;
import javax.swing.ImageIcon;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.wstgmapper.ui.WstgMapperPanel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/**
 * Main entry point for the OWASP WSTG Mapper add-on.
 *
 * <p>It boots the shared data services, restores the session-backed checklist state, registers the
 * alert consumer, and attaches the status panel to the ZAP UI. In practice this class is the glue
 * that turns the bundled JSON resources and helper classes into a live add-on.
 */
public class ExtensionWstgMapper extends ExtensionAdaptor {

    public static final String NAME = "ExtensionWstgMapper";
    public static final String PREFIX = "wstgmapper";
    private static final String ICON_PATH = "/org/zaproxy/addon/wstgmapper/resources/icon/wstg.png";
    private static final String DEFAULT_SESSION_FILE_NAME = "wstgmapper-default.xml";

    private static final Logger LOGGER = LogManager.getLogger(ExtensionWstgMapper.class);

    private static ImageIcon icon;

    private WstgMapperData data;
    private WstgMapperMappingManager mappingManager;
    private WstgMapperParam param;
    private WstgMapperChecklistManager checklistManager;
    private WstgMapperAlertConsumer alertConsumer;
    private CoverageCalculator coverageCalculator;
    private TechStackDetector techStackDetector;
    private WstgMapperPanel panel;

    public ExtensionWstgMapper() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void init() {
        try {
            data = new WstgMapperData();
        } catch (IOException e) {
            LOGGER.error("Failed to load WSTG Mapper data.", e);
        }
        try {
            mappingManager = new WstgMapperMappingManager();
        } catch (IOException e) {
            LOGGER.error("Failed to load WSTG Mapper mappings.", e);
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        param = new WstgMapperParam();
        loadParamForSession(Model.getSingleton().getSession());

        extensionHook.addSessionListener(new SessionChangedListenerImpl());

        if (data != null && mappingManager != null) {
            checklistManager = new WstgMapperChecklistManager(param);
            coverageCalculator = new CoverageCalculator(data, checklistManager, mappingManager);
            techStackDetector = new TechStackDetector(mappingManager, data);
            alertConsumer = new WstgMapperAlertConsumer(mappingManager, checklistManager);
            alertConsumer.register();
            bootstrapExistingAlertsAsync();

            if (hasView()) {
                panel =
                        new WstgMapperPanel(
                                data,
                                mappingManager,
                                checklistManager,
                                coverageCalculator,
                                techStackDetector);
                extensionHook.getHookView().addStatusPanel(panel);
            }
        }
    }

    /**
     * Binds {@link #param} to the storage for the given session.
     *
     * <p>Saved sessions use a sidecar XML file. Unsaved sessions also use a sidecar in the ZAP
     * sessions directory, but it is reset to an empty config each time a new unsaved session is
     * loaded so the panel starts clean at `0%`.
     */
    private void loadParamForSession(Session session) {
        String sessionFileName = session == null ? null : session.getFileName();
        File sessionFile =
                hasPersistedSession(sessionFileName)
                        ? getWstgMapperSessionFile(sessionFileName)
                        : getUnsavedSessionFile();
        if (!hasPersistedSession(sessionFileName)) {
            LOGGER.debug("Resetting WSTG Mapper state for unsaved session at: {}", sessionFile);
            sessionFile.getParentFile().mkdirs();
            ZapXmlConfiguration config = new ZapXmlConfiguration();
            config.setFile(sessionFile);
            param.load(config);
            param.saveNow();
            return;
        }

        LOGGER.debug("Loading WSTG Mapper session data from: {}", sessionFile);
        if (!sessionFile.exists()) {
            LOGGER.debug("Session sidecar not found, creating defaults at: {}", sessionFile);
            sessionFile.getParentFile().mkdirs();
            ZapXmlConfiguration config = new ZapXmlConfiguration();
            config.setFile(sessionFile);
            param.load(config);
            return;
        }
        try {
            ZapXmlConfiguration config = new ZapXmlConfiguration(sessionFile);
            param.load(config);
        } catch (Exception e) {
            LOGGER.error("Failed to load WSTG Mapper session data from {}", sessionFile, e);
            sessionFile.getParentFile().mkdirs();
            ZapXmlConfiguration config = new ZapXmlConfiguration();
            config.setFile(sessionFile);
            param.load(config);
        }
    }

    /**
     * Returns the companion WSTG data file for the given ZAP session.
     *
     * <ul>
     *   <li>Saved session at {@code /path/to/myproject.session} → {@code
     *       /path/to/myproject.session.wstgmapper.xml}
     *   <li>Unsaved session → {@code <zap-home>/sessions/wstgmapper-default.xml}
     * </ul>
     */
    static boolean hasPersistedSession(String sessionFileName) {
        return sessionFileName != null && !sessionFileName.isEmpty();
    }

    static File getUnsavedSessionFile() {
        File sessionsDir = new File(Constant.getZapHome(), "sessions");
        sessionsDir.mkdirs();
        return new File(sessionsDir, DEFAULT_SESSION_FILE_NAME);
    }

    static File getWstgMapperSessionFile(String sessionFileName) {
        return new File(sessionFileName + ".wstgmapper.xml");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        icon = null;
        if (param != null) {
            param.saveNow();
        }
        if (alertConsumer != null) {
            alertConsumer.unregister();
        }
        if (panel != null) {
            panel.cleanup();
        }
        if (checklistManager != null && panel != null) {
            checklistManager.removeListener(panel);
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    @Override
    public String getUIName() {
        return "WSTG Mapper";
    }

    public static ImageIcon getIcon() {
        if (icon == null) {
            var resource = ExtensionWstgMapper.class.getResource(ICON_PATH);
            if (resource != null) {
                icon = DisplayUtils.getScaledIcon(resource);
            }
        }
        return icon;
    }

    // ---- Session persistence ----

    private void bootstrapExistingAlertsAsync() {
        if (alertConsumer == null) {
            return;
        }
        Thread bootstrapThread =
                new Thread(alertConsumer::bootstrapExistingAlerts, "wstgmapper-alert-bootstrap");
        bootstrapThread.setDaemon(true);
        bootstrapThread.start();
    }

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {
            if (param == null || checklistManager == null) {
                return;
            }
            String sessionFileName = session == null ? null : session.getFileName();
            if (hasPersistedSession(sessionFileName)) {
                File newWstgFile = getWstgMapperSessionFile(sessionFileName);
                if (!newWstgFile.exists() && param.getConfig() != null) {
                    File oldFile = param.getConfig().getFile();
                    if (oldFile == null) {
                        newWstgFile.getParentFile().mkdirs();
                        param.getConfig().setFile(newWstgFile);
                        param.saveNow();
                        LOGGER.debug("Persisted transient WSTG Mapper state to {}", newWstgFile);
                    } else if (oldFile.exists()
                            && oldFile.length() > 0
                            && !oldFile.equals(newWstgFile)) {
                        try {
                            newWstgFile.getParentFile().mkdirs();
                            Files.copy(oldFile.toPath(), newWstgFile.toPath());
                            LOGGER.debug(
                                    "Migrated WSTG Mapper sidecar from {} to {}",
                                    oldFile,
                                    newWstgFile);
                        } catch (IOException e) {
                            LOGGER.error("Failed to migrate WSTG Mapper session data", e);
                        }
                    }
                }
            }
            loadParamForSession(session);
            checklistManager.clearTriggered();
            checklistManager.clearDetectedTechnologies();
            checklistManager.notifyChanged();
            bootstrapExistingAlertsAsync();
        }

        @Override
        public void sessionAboutToChange(Session session) {
            if (param != null) {
                param.saveNow();
            }
        }

        @Override
        public void sessionScopeChanged(Session session) {}

        @Override
        public void sessionModeChanged(org.parosproxy.paros.control.Control.Mode mode) {}
    }
}
