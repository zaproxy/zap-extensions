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
package org.zaproxy.addon.encoder;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class EncoderConfig {

    private static final Logger LOGGER = LogManager.getLogger(EncoderConfig.class);

    private static final String TABS_KEY = "tabs";
    private static final String TAB_KEY = "tab";
    private static final String TAB_PATH = TABS_KEY + "." + TAB_KEY;
    private static final String TAB_NAME_KEY = "name";
    private static final String OUTPUT_PANELS_KEY = "outputpanels";
    private static final String OUTPUT_PANEL_KEY = "outputpanel";
    private static final String OUTPUT_PANEL_PATH = OUTPUT_PANELS_KEY + "." + OUTPUT_PANEL_KEY;
    private static final String OUTPUT_PANEL_NAME_KEY = "name";
    private static final String OUTPUT_PANEL_SCRIPT_KEY = "processorId";
    private static final String CONFIG_BASE = "addOnData/encoder/config/";
    private static final String CONFIG_FILE = CONFIG_BASE + "encoder-config.xml";
    private static final String DEFAULT_CONFIG_FILE_NAME = "encoder-default.xml";
    private static final String DEFAULT_CONFIG_FILE = CONFIG_BASE + DEFAULT_CONFIG_FILE_NAME;
    private static final String DEFAULT_BUNDLED_CONFIG_FILE =
            "resources/" + DEFAULT_CONFIG_FILE_NAME;

    private static final String DIVIDER_LOCATION_KEY = "dividerLocation";

    private EncoderConfig() {
        // Utility Class
    }

    public static Data loadConfig() throws ConfigurationException, IOException {
        Path config = getConfigPath(CONFIG_FILE);
        if (Files.notExists(config)) {
            return loadDefaultConfig();
        }
        return loadConfig(config);
    }

    public static Data loadDefaultConfig() throws ConfigurationException, IOException {
        Path defaultConfig = getConfigPath(DEFAULT_CONFIG_FILE);
        if (Files.notExists(defaultConfig)) {
            Files.createDirectories(defaultConfig.getParent());
            try (InputStream in =
                    EncoderConfig.class.getResourceAsStream(DEFAULT_BUNDLED_CONFIG_FILE)) {
                Files.copy(in, defaultConfig);
            } catch (IOException e) {
                LOGGER.warn("Failed to create the default configuration file.", e);

                try (InputStream in =
                        EncoderConfig.class.getResourceAsStream(DEFAULT_BUNDLED_CONFIG_FILE)) {
                    return loadConfig(new ZapXmlConfiguration(in));
                } catch (IOException e1) {
                    LOGGER.error("Failed to load the default bundled configuration file.", e1);
                }
                return new Data();
            }
        }
        return loadConfig(defaultConfig);
    }

    private static Path getConfigPath(String configName) {
        return Paths.get(Constant.getZapHome(), configName);
    }

    private static Data loadConfig(Path file) throws ConfigurationException {
        return loadConfig(new ZapXmlConfiguration(file.toFile()));
    }

    private static Data loadConfig(ZapXmlConfiguration config) {
        List<TabModel> tabs = new ArrayList<>();
        List<HierarchicalConfiguration> tabConfigs = config.configurationsAt(TAB_PATH);
        for (HierarchicalConfiguration tabConfig : tabConfigs) {
            String tabName = tabConfig.getString(TAB_NAME_KEY);
            TabModel tab = new TabModel();
            tab.setName(tabName);

            List<OutputPanelModel> panels = new ArrayList<>();
            List<HierarchicalConfiguration> panelConfigs =
                    tabConfig.configurationsAt(OUTPUT_PANEL_PATH);
            for (HierarchicalConfiguration panelConfig : panelConfigs) {
                String panelName = panelConfig.getString(OUTPUT_PANEL_NAME_KEY);
                String script = panelConfig.getString(OUTPUT_PANEL_SCRIPT_KEY);
                OutputPanelModel panel = new OutputPanelModel();
                panel.setName(panelName);
                panel.setProcessorId(script);
                panels.add(panel);
            }

            tab.setOutputPanels(panels);
            tabs.add(tab);
        }
        return new Data(
                tabs, config.getDouble(DIVIDER_LOCATION_KEY, Data.DEFAULT_DIVIDER_LOCATION));
    }

    public static void saveConfig(Data data) throws ConfigurationException, IOException {
        saveConfig(getConfigPath(CONFIG_FILE), data);
    }

    private static void saveConfig(Path file, Data data)
            throws ConfigurationException, IOException {
        List<TabModel> tabs = data.getTabs();
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        int t = 0;
        for (TabModel tab : tabs) {
            String elementTabKey = TAB_PATH + "(" + t++ + ").";
            config.setProperty(elementTabKey + TAB_NAME_KEY, tab.getName());
            int p = 0;
            for (OutputPanelModel panel : tab.getOutputPanels()) {
                String elementPanelKey = elementTabKey + OUTPUT_PANEL_PATH + "(" + p++ + ").";
                config.setProperty(elementPanelKey + OUTPUT_PANEL_NAME_KEY, panel.getName());
                config.setProperty(
                        elementPanelKey + OUTPUT_PANEL_SCRIPT_KEY, panel.getProcessorId());
            }
        }
        config.setProperty(DIVIDER_LOCATION_KEY, data.getDividerLocation());

        Files.createDirectories(file.getParent());
        config.save(file.toFile());
    }

    /** Holder for encoder config: tab layout and divider position. */
    public static final class Data {
        /** Default proportion (0.0–1.0) for the input area in the main dialog. */
        public static final double DEFAULT_DIVIDER_LOCATION = 0.2;

        private final List<TabModel> tabs;
        private final double dividerLocation;

        /**
         * Creates data with default tabs and divider location from config, or empty tabs and
         * default divider if loading fails.
         */
        public Data() {
            Data fromDefault = null;
            try {
                fromDefault = EncoderConfig.loadDefaultConfig();
            } catch (ConfigurationException | IOException e) {
                LOGGER.warn(
                        "Failed to load default encoder config, using empty tabs and default divider.",
                        e);
            }
            if (fromDefault != null) {
                this.tabs = new ArrayList<>(fromDefault.getTabs());
                this.dividerLocation = fromDefault.getDividerLocation();
            } else {
                this.tabs = new ArrayList<>();
                this.dividerLocation = DEFAULT_DIVIDER_LOCATION;
            }
        }

        /**
         * Validates divider location: if in range 0.0–1.0 it is used, otherwise the default is
         * used.
         */
        public Data(List<TabModel> tabs, double dividerLocation) {
            this.tabs = new ArrayList<>(tabs);
            this.dividerLocation =
                    dividerLocation >= 0.0 && dividerLocation <= 1.0
                            ? dividerLocation
                            : DEFAULT_DIVIDER_LOCATION;
        }

        public List<TabModel> getTabs() {
            return new ArrayList<>(tabs);
        }

        public double getDividerLocation() {
            return dividerLocation;
        }
    }
}
