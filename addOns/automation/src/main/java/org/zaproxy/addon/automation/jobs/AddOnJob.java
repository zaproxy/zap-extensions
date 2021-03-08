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
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.configuration.XMLPropertiesConfiguration;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.control.AddOnCollection;
import org.zaproxy.zap.extension.autoupdate.ExtensionAutoUpdate;
import org.zaproxy.zap.extension.autoupdate.OptionsParamCheckForUpdates;

public class AddOnJob extends AutomationJob {

    public static final String JOB_NAME = "addOns";

    private static final String PARAM_UPDATE_ADDONS = "updateAddOns";

    private boolean updateAddOns = true;

    public AddOnJob() {}

    @SuppressWarnings("unchecked")
    @Override
    public void runJob(
            AutomationEnvironment env, LinkedHashMap<?, ?> jobData, AutomationProgress progress) {

        ExtensionAutoUpdate extAutoUpd =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutoUpdate.class);
        if (updateAddOns) {
            try {
                // Unfortunately we need to do some nasty reflection :/
                Method glviMethod = extAutoUpd.getClass().getDeclaredMethod("getLatestVersionInfo");
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
        Object installAddOnsObj = jobData.get("install");
        if (installAddOnsObj != null) {
            if (installAddOnsObj instanceof ArrayList<?>) {
                ArrayList<?> instAddOns = (ArrayList<?>) installAddOnsObj;
                String result = extAutoUpd.installAddOns((ArrayList<String>) instAddOns);
                if (result.length() > 0) {
                    progress.error(result);
                    return;
                }
            } else {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.addons.addon.data", installAddOnsObj));
            }
        }

        Object uninstallAddOnsObj = jobData.get("uninstall");
        if (uninstallAddOnsObj != null) {
            if (uninstallAddOnsObj instanceof ArrayList<?>) {
                ArrayList<?> uninstAddOns = (ArrayList<?>) uninstallAddOnsObj;
                String result = extAutoUpd.uninstallAddOns((ArrayList<String>) uninstAddOns);
                if (result.length() > 0) {
                    progress.error(result);
                    return;
                }
            } else {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.addons.addon.data", uninstallAddOnsObj));
            }
        }
    }

    @Override
    public boolean applyCustomParameter(String name, String value) {
        switch (name) {
            case PARAM_UPDATE_ADDONS:
                updateAddOns = Boolean.parseBoolean(value);
                return true;
            default:
                // Ignore
                break;
        }
        return false;
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_UPDATE_ADDONS, "true");
        return map;
    }

    public String getExtraConfigFileData() {
        return "    install:                           # A list of non standard add-ons to install from the ZAP Marketplace\n"
                + "    uninstall:                         # A list of standard add-ons to uninstall\n";
    }

    public boolean isUpdateAddOns() {
        return updateAddOns;
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
}
