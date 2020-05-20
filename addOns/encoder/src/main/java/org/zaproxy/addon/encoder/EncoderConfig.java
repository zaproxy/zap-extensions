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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class EncoderConfig {

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
    private static final String CONFIG_FILE_NAME = CONFIG_BASE + "encoder-config.xml";
    private static final String DEFAULT_CONFIG_FILE_NAME = CONFIG_BASE + "encoder-default.xml";

    public static List<TabModel> loadConfig() throws ConfigurationException, IOException {
        return loadConfig(getConfigFile(CONFIG_FILE_NAME));
    }

    public static List<TabModel> loadDefaultConfig() throws ConfigurationException, IOException {
        return loadConfig(getConfigFile(DEFAULT_CONFIG_FILE_NAME));
    }

    private static File getConfigFile(String configName) throws IOException {
        File file = new File(Constant.getZapHome() + "/" + configName);
        if (!file.exists()) {
            file.createNewFile();
        }
        return file;
    }

    public static List<TabModel> loadConfig(File file) throws ConfigurationException {
        ZapXmlConfiguration config = new ZapXmlConfiguration(file);

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
        return tabs;
    }

    public static void saveConfig(List<TabModel> tabs) throws ConfigurationException, IOException {
        saveConfig(getConfigFile(CONFIG_FILE_NAME), tabs);
    }

    public static void saveConfig(File file, List<TabModel> tabs) throws ConfigurationException {
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

        config.save(file);
    }
}
