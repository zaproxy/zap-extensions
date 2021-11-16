/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation.jobs;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.configuration.XMLPropertiesConfiguration;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.gui.AddOnJobDialog;
import org.zaproxy.zap.control.AddOnCollection;
import org.zaproxy.zap.extension.autoupdate.ExtensionAutoUpdate;
import org.zaproxy.zap.extension.autoupdate.OptionsParamCheckForUpdates;

public class AddOnJob extends AutomationJob {

    public static final String JOB_NAME = "addOns";

    private static final String PARAM_UPDATE_ADDONS = "updateAddOns";

    private Parameters parameters = new Parameters();
    private Data data;

    private boolean disableAutoupdate = true;

    public AddOnJob() {
        data = new Data(this, this.parameters);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData == null) {
            return;
        }
        JobUtils.applyParamsToObject(
                (LinkedHashMap<?, ?>) jobData.get("parameters"),
                this.parameters,
                this.getName(),
                null,
                progress);
        for (Object key : jobData.keySet()) {
            if ("install".equals(key)) {
                Object installAddOnsObj = jobData.get(key);
                if (installAddOnsObj == null) {
                    continue;
                }
                if (installAddOnsObj instanceof ArrayList<?>) {
                    try {
                        this.data.setInstall((ArrayList<String>) installAddOnsObj);
                    } catch (Exception e) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.addons.addon.data", installAddOnsObj));
                    }
                } else {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.addons.addon.data", installAddOnsObj));
                }
            } else if ("uninstall".equals(key)) {
                Object uninstallAddOnsObj = jobData.get(key);
                if (uninstallAddOnsObj == null) {
                    continue;
                }
                if (uninstallAddOnsObj instanceof ArrayList<?>) {
                    try {
                        this.data.setUninstall((ArrayList<String>) uninstallAddOnsObj);
                    } catch (Exception e) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.addons.addon.data", uninstallAddOnsObj));
                    }
                } else {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.addons.addon.data", uninstallAddOnsObj));
                }
            }
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        // Nothing to do
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        ExtensionAutoUpdate extAutoUpd =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutoUpdate.class);
        if (this.parameters.getUpdateAddOns()) {
            if (this.disableAutoupdate) {
                progress.info(Constant.messages.getString("automation.info.addons.noupdate"));
            } else {
                try {
                    // Unfortunately we need to do some nasty reflection :/
                    Method glviMethod =
                            extAutoUpd.getClass().getDeclaredMethod("getLatestVersionInfo");
                    glviMethod.setAccessible(true);
                    AddOnCollection aoc = (AddOnCollection) glviMethod.invoke(extAutoUpd);

                    OptionsParamCheckForUpdates options = new OptionsParamCheckForUpdates();
                    options.load(new XMLPropertiesConfiguration());
                    options.setCheckOnStart(true);
                    options.setCheckAddonUpdates(true);
                    options.setInstallAddonUpdates(true);

                    Method cfuMethod =
                            extAutoUpd
                                    .getClass()
                                    .getDeclaredMethod(
                                            "checkForAddOnUpdates",
                                            AddOnCollection.class,
                                            OptionsParamCheckForUpdates.class);
                    cfuMethod.setAccessible(true);
                    cfuMethod.invoke(extAutoUpd, aoc, options);

                    Method waitMethod =
                            extAutoUpd.getClass().getDeclaredMethod("waitForDownloadInstalls");
                    waitMethod.setAccessible(true);
                    waitMethod.invoke(extAutoUpd);

                } catch (Exception e) {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.addons.update", e.getMessage()));
                    return;
                }
            }
        }
        if (!this.data.getInstall().isEmpty()) {
            String result = extAutoUpd.installAddOns(this.data.getInstall());
            if (result.length() > 0) {
                progress.error(result);
                return;
            }
        }
        if (!this.data.getUninstall().isEmpty()) {
            String result = extAutoUpd.uninstallAddOns(this.data.getUninstall());
            if (result.length() > 0) {
                progress.error(result);
            }
        }
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_UPDATE_ADDONS, "true");
        return map;
    }

    @Override
    public String getExtraConfigFileData() {
        return "    install:                           # A list of non standard add-ons to install from the ZAP Marketplace\n"
                + "    uninstall:                         # A list of standard add-ons to uninstall\n";
    }

    public boolean isUpdateAddOns() {
        return this.parameters.getUpdateAddOns();
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Order getOrder() {
        return Order.CONFIGS;
    }

    @Override
    public Object getParamMethodObject() {
        return null;
    }

    @Override
    public String getParamMethodName() {
        return null;
    }

    @Override
    public void showDialog() {
        new AddOnJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "automation.dialog.addon.summary",
                this.getData().getInstall().toString(),
                this.getData().getUninstall().toString());
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return parameters;
    }

    public static class Data extends JobData {
        private Parameters parameters;
        private List<String> install;
        private List<String> uninstall;

        public Data(AutomationJob job, Parameters parameters) {
            super(job);
            this.parameters = parameters;
        }

        public Parameters getParameters() {
            return parameters;
        }

        public List<String> getInstall() {
            if (install == null) {
                return Collections.emptyList();
            }
            return install.stream().collect(Collectors.toList());
        }

        public void setInstall(List<String> install) {
            this.install = install;
        }

        public List<String> getUninstall() {
            if (uninstall == null) {
                return Collections.emptyList();
            }
            return uninstall.stream().collect(Collectors.toList());
        }

        public void setUninstall(List<String> uninstall) {
            this.uninstall = uninstall;
        }
    }

    public static class Parameters extends AutomationData {
        private boolean updateAddOns = false;

        public boolean getUpdateAddOns() {
            return updateAddOns;
        }

        public void setUpdateAddOns(boolean updateAddOns) {
            this.updateAddOns = updateAddOns;
        }
    }
}
