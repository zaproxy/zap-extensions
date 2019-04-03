/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.bugtracker;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.log4j.Logger;
import org.parosproxy.paros.common.AbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;

public class BugTrackerGithubParam extends AbstractParam {

    private static final Logger logger = Logger.getLogger(BugTrackerGithubParam.class);

    private static final String GITHUB_BASE_KEY = "github";
    
    private static final String ALL_CONFIGS_KEY = GITHUB_BASE_KEY + ".configs.config";
    
    private static final String CONFIG_NAME_KEY = "name";
    private static final String CONFIG_PASSWORD_KEY = "password";
    private static final String CONFIG_REPO_URL_KEY = "repoUrl";
    
    private static final String CONFIRM_REMOVE_CONFIG_KEY = GITHUB_BASE_KEY + ".confirmRemoveConfig";

    private List<BugTrackerGithubConfigParams> configs = null;
    
    private boolean confirmRemoveConfig = true;

    public BugTrackerGithubParam() {
    }

    @Override
    protected void parse() {
        try {
            List<HierarchicalConfiguration> fields = ((HierarchicalConfiguration) getConfig()).configurationsAt(ALL_CONFIGS_KEY);
            this.configs = new ArrayList<>(fields.size());
            List<String> tempConfigsNames = new ArrayList<>(fields.size());
            for (HierarchicalConfiguration sub : fields) {
                String name = sub.getString(CONFIG_NAME_KEY, "");
                String password = sub.getString(CONFIG_PASSWORD_KEY, "");
                String repoUrl = sub.getString(CONFIG_REPO_URL_KEY, "");
                if (!"".equals(name) && !tempConfigsNames.contains(name)) {
                    this.configs.add(new BugTrackerGithubConfigParams(name, password, repoUrl));
                    tempConfigsNames.add(name);
                }
            }
        } catch (ConversionException e) {
            logger.error("Error while loading github configs: " + e.getMessage(), e);
        }

        try {
            this.confirmRemoveConfig = getConfig().getBoolean(CONFIRM_REMOVE_CONFIG_KEY, true);
        } catch (ConversionException e) {
            logger.error("Error while loading the confirm remove config option: " + e.getMessage(), e);
        }
    }

    @ZapApiIgnore
    public List<BugTrackerGithubConfigParams> getConfigs() {
        return configs;
    }

    @ZapApiIgnore
    public void setConfigs(List<BugTrackerGithubConfigParams> configs) {
        this.configs = new ArrayList<>(configs);
        
        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_CONFIGS_KEY);

        for (int i = 0, size = configs.size(); i < size; ++i) {
            String elementBaseKey = ALL_CONFIGS_KEY + "(" + i + ").";
            BugTrackerGithubConfigParams config = configs.get(i);
            
            getConfig().setProperty(elementBaseKey + CONFIG_NAME_KEY, config.getName());
            getConfig().setProperty(elementBaseKey + CONFIG_PASSWORD_KEY, config.getPassword());
            getConfig().setProperty(elementBaseKey + CONFIG_REPO_URL_KEY, config.getRepoUrl());
        }
    }

    /**
     * Adds a new config with the given {@code name}.
     * <p>
     * The call to this method has no effect if the given {@code name} is null or empty, or a config with the given name already
     * exist.
     *
     * @param name the name of the config that will be added
     */
    public void addConfig(String name, String password, String repoUrl) {
        if (name == null || name.isEmpty()) {
            return;
        }

        for (Iterator<BugTrackerGithubConfigParams> it = configs.iterator(); it.hasNext();) {
            if (name.equals(it.next().getName())) {
                return;
            }
        }

        this.configs.add(new BugTrackerGithubConfigParams(name, password, repoUrl));
    }

    /**
     * Removes the config with the given {@code name}.
     * <p>
     * The call to this method has no effect if the given {@code name} is null or empty, or a config with the given {@code name}
     * does not exist.
     *
     * @param name the name of the config that will be removed
     */
    public void removeConfig(String name, String password, String repoUrl) {
        if (name == null || name.isEmpty()) {
            return;
        }

        for (Iterator<BugTrackerGithubConfigParams> it = configs.iterator(); it.hasNext();) {
            BugTrackerGithubConfigParams config = it.next();
            if (name.equals(config.getName())) {
                it.remove();
                break;
            }
        }
    }
    
    @ZapApiIgnore
    public boolean isConfirmRemoveConfig() {
        return this.confirmRemoveConfig;
    }
    
    @ZapApiIgnore
    public void setConfirmRemoveConfig(boolean confirmRemove) {
        this.confirmRemoveConfig = confirmRemove;
        getConfig().setProperty(CONFIRM_REMOVE_CONFIG_KEY, Boolean.valueOf(confirmRemoveConfig));
    }

}
