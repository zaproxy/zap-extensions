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

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;

/**
 * Manage add-ons - this job should no longer be used - see
 * https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-addons/
 *
 * @deprecated
 */
@Deprecated
public class AddOnJob extends AutomationJob {

    public static final String JOB_NAME = "addOns";

    private Parameters parameters = new Parameters();
    private Data data;

    public AddOnJob() {
        data = new Data(this, this.parameters);
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        progress.warn(Constant.messages.getString("automation.error.addons.deprecated"));
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        progress.warn(Constant.messages.getString("automation.error.addons.deprecated"));
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        progress.warn(Constant.messages.getString("automation.error.addons.deprecated"));
    }

    public boolean isUpdateAddOns() {
        return this.parameters.getUpdateAddOns();
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public String getConfigFileData() {
        // Do not generate any config file data
        return "";
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
