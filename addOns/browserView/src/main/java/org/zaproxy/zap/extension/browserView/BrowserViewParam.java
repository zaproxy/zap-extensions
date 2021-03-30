/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.browserView;

import org.apache.commons.configuration.ConversionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.common.AbstractParam;

/** The class to handle the (persisted) configurations of "Browser View" add-on. */
public class BrowserViewParam extends AbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(BrowserViewParam.class);

    /**
     * The current version of the configurations. Used to keep track of configuration changes
     * between releases, in case changes/updates are needed.
     *
     * <p>It only needs to be incremented for configuration changes (not releases of the add-on).
     *
     * @see #CONFIG_VERSION_KEY
     * @see #NO_CONFIG_VERSION
     * @see #ERROR_READING_CONFIG_VERSION
     * @see #updateConfigFile()
     */
    private static final int CURRENT_CONFIG_VERSION = 1;

    /**
     * A dummy version number used at runtime to indicate that the configurations were never
     * persisted.
     *
     * @see #CURRENT_CONFIG_VERSION
     * @see #ERROR_READING_CONFIG_VERSION
     */
    private static final int NO_CONFIG_VERSION = -1;

    /**
     * A dummy version number used at runtime to indicate that an error occurred while reading the
     * version from the file.
     *
     * @see #CURRENT_CONFIG_VERSION
     * @see #NO_CONFIG_VERSION
     */
    private static final int ERROR_READING_CONFIG_VERSION = -2;

    /** The base configuration key for all "Browser View" configurations. */
    private static final String PARAM_BASE_KEY = "browserView";

    /**
     * The configuration key for the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = PARAM_BASE_KEY + ".configVersion";

    /** The configuration key for the state of "warn on JavaFX initialisation error". */
    private static final String PARAM_WARN_ON_JAVA_FX_INIT_ERROR =
            PARAM_BASE_KEY + ".warnErrorJavaFX";

    private static final boolean PARAM_WARN_ON_JAVA_FX_INIT_ERROR_DEFAULT_VALUE = true;

    private boolean warnOnJavaFXInitError = PARAM_WARN_ON_JAVA_FX_INIT_ERROR_DEFAULT_VALUE;

    @Override
    protected void parse() {
        updateConfigFile();

        warnOnJavaFXInitError =
                getBoolean(
                        PARAM_WARN_ON_JAVA_FX_INIT_ERROR,
                        PARAM_WARN_ON_JAVA_FX_INIT_ERROR_DEFAULT_VALUE);
    }

    /**
     * Updates the configurations in the file, if needed.
     *
     * <p>The following steps are made:
     *
     * <ol>
     *   <li>Read the version of the configurations that are in the file;
     *   <li>Check if the version read is the latest version;
     *   <li>If it's not at the latest version, update the configurations.
     * </ol>
     *
     * @see #CURRENT_CONFIG_VERSION
     * @see #isLatestConfigVersion(int)
     * @see #updateConfigsFromVersion(int)
     */
    private void updateConfigFile() {
        int configVersion;
        try {
            configVersion = getConfig().getInt(CONFIG_VERSION_KEY, NO_CONFIG_VERSION);
        } catch (ConversionException e) {
            LOGGER.error(
                    "Error while getting the version of the configurations: {}", e.getMessage(), e);
            configVersion = ERROR_READING_CONFIG_VERSION;
        }

        if (!isLatestConfigVersion(configVersion)) {
            updateConfigsFromVersion(configVersion);
        }
    }

    /**
     * Tells whether or not the given {@code version} number is the latest version, that is, is the
     * same version number as the version of the running code.
     *
     * @param version the version that will be checked
     * @return {@code true} if the given {@code version} is the latest version, {@code false}
     *     otherwise
     * @see #CURRENT_CONFIG_VERSION
     * @see #updateConfigFile()
     */
    private static boolean isLatestConfigVersion(int version) {
        return version == CURRENT_CONFIG_VERSION;
    }

    /**
     * Called when the configuration version in the file is different than the version of the
     * running code.
     *
     * <p>Any required configuration changes/updates should be added to this method.
     *
     * <p>If the given {@code fileVersion} is:
     *
     * <ul>
     *   <li>&lt; {@code CURRENT_CONFIG_VERSION} - expected case, the configurations are
     *       changed/updated to the current version. Before returning the version in the
     *       configuration file is updated to the current version.
     *   <li>&gt; {@code CURRENT_CONFIG_VERSION} - no changes/updates are made, the method logs a
     *       warn and returns;
     *   <li>{@code NO_CONFIG_VERSION} - only the current version is written to the configuration
     *       file;
     *   <li>{@code ERROR_READING_CONFIG_VERSION} - no changes/updates are made, the method logs a
     *       warn and returns.
     * </ul>
     *
     * <p>
     *
     * @param fileVersion the version of the configurations in the file
     * @see #CURRENT_CONFIG_VERSION
     * @see #NO_CONFIG_VERSION
     * @see #ERROR_READING_CONFIG_VERSION
     * @see #updateConfigFile()
     */
    private void updateConfigsFromVersion(int fileVersion) {
        if (fileVersion == CURRENT_CONFIG_VERSION) {
            return;
        }

        if (fileVersion == ERROR_READING_CONFIG_VERSION) {
            // There's not much that can be done (quickly and easily)... log and return.
            LOGGER.warn("Configurations might not be in expected state, errors might happen...");
            return;
        }

        if (fileVersion != NO_CONFIG_VERSION) {
            if (fileVersion > CURRENT_CONFIG_VERSION) {
                LOGGER.warn(
                        "Configurations will not be updated, file version (v{}) is greater than the version of running code (v{}), errors might happen...",
                        fileVersion,
                        CURRENT_CONFIG_VERSION);
                return;
            }
            LOGGER.info(
                    "Updating configurations from v{} to v{}", fileVersion, CURRENT_CONFIG_VERSION);
        }

        switch (fileVersion) {
            case NO_CONFIG_VERSION:
                // No updates/changes needed, the configurations were not previously persisted
                // and the current version is already written at the end of the method.
                break;
        }

        getConfig().setProperty(CONFIG_VERSION_KEY, Integer.valueOf(CURRENT_CONFIG_VERSION));
    }

    /**
     * Tells whether or not the user should be warned if an error occurred while initialising
     * JavaFX.
     *
     * @return {@code true} if the user should be warned, {@code false} otherwise
     * @see #setWarnOnJavaFXInitError(boolean)
     */
    boolean isWarnOnJavaFXInitError() {
        return warnOnJavaFXInitError;
    }

    /**
     * Sets whether or not the user should be warned if an error occurred while initialising JavaFX.
     *
     * @param warn {@code true} if the user should be warned, {@code false} otherwise
     * @see #isWarnOnJavaFXInitError()
     */
    void setWarnOnJavaFXInitError(boolean warn) {
        if (warnOnJavaFXInitError != warn) {
            warnOnJavaFXInitError = warn;

            getConfig()
                    .setProperty(
                            PARAM_WARN_ON_JAVA_FX_INIT_ERROR,
                            Boolean.valueOf(warnOnJavaFXInitError));
        }
    }
}
