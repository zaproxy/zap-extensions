/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.gui.ActiveScanPolicyJobDialog;
import org.zaproxy.addon.automation.jobs.PolicyDefinition.Rule;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.internal.GspmPolicyOperations;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.ScanPolicy;

public class ActiveScanPolicyJob extends AutomationJob {

    public static final String JOB_NAME = "activeScan-policy";

    private static final Logger LOGGER = LogManager.getLogger(ActiveScanPolicyJob.class);

    private static final String PARAM_NAME = "name";

    private static final String GLOBAL_SCAN_POLICY_TOOL = "ascan";

    private ExtensionActiveScan extAScan;

    private Supplier<GspmRegistry> gspmRegistrySupplier = ActiveScanPolicyJob::getGspmRegistry;

    private Parameters parameters = new Parameters();
    private PolicyDefinition policyDefinition = new PolicyDefinition();
    private Data data;

    public ActiveScanPolicyJob() {
        data = new Data(this, this.parameters, this.policyDefinition);
    }

    private ExtensionActiveScan getExtAScan() {
        if (extAScan == null) {
            extAScan =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionActiveScan.class);
        }
        return extAScan;
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData == null) {
            return;
        }

        for (Object key : jobData.keySet().toArray()) {
            switch (key.toString()) {
                case "parameters":
                    LinkedHashMap<?, ?> params = (LinkedHashMap<?, ?>) jobData.get(key);
                    JobUtils.applyParamsToObject(
                            params, this.parameters, this.getName(), null, progress);
                    break;
                case "policyDefinition":
                    // Parse the policy defn
                    policyDefinition.parsePolicyDefinition(
                            jobData.get(key), this.getName(), progress);
                    break;
                case "tests":
                    // Handled before we get here
                    break;
                default:
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.element.unknown", this.getName(), key));

                    break;
            }
        }
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_NAME, "");
        return map;
    }

    @Override
    public boolean applyCustomParameter(String name, String value) {
        if (PARAM_NAME.equals(name)) {
            return true;
        }
        return false;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        if (Constant.isDevMode()) {
            runJobWithGlobalScanPolicy(progress);
            return;
        }
        try {
            ScanPolicy scanPolicy = this.getScanPolicy(progress);

            List<String> allNames = getExtAScan().getPolicyManager().getAllPolicyNames();
            if (allNames.contains(scanPolicy.getName())) {
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.scanpolicy.exists",
                                this.getName(),
                                scanPolicy.getName()));
                return;
            }
            getExtAScan().getPolicyManager().savePolicy(scanPolicy);
        } catch (ConfigurationException e) {
            progress.error(
                    Constant.messages.getString("automation.dialog.error.misc", e.getMessage()));
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * Sets how to get the registry of the Global Scan Policy Manager, used when running with the
     * dev mode.
     *
     * @param supplier the supplier of the registry, might supply {@code null} if not available.
     */
    void setGspmRegistrySupplier(Supplier<GspmRegistry> supplier) {
        gspmRegistrySupplier = supplier;
    }

    private static GspmRegistry getGspmRegistry() {
        ExtensionCommonlib extCommonlib =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionCommonlib.class);
        return extCommonlib != null ? extCommonlib.getGspmRegistry() : null;
    }

    /** Adds the policy to the Global Scan Policy Manager, with the same settings as the scan. */
    private void runJobWithGlobalScanPolicy(AutomationProgress progress) {
        String jobName = this.getName();
        String policyName = this.getData().getParameters().getName();
        GspmRegistry registry = gspmRegistrySupplier.get();
        if (registry == null) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.scanpolicy.gspm.unavailable", jobName, policyName));
            return;
        }

        PolicyDefinition definition = this.getData().getPolicyDefinition();
        // Not defined, the policy has just the defaults.
        boolean defined = definition.getDefaultStrength() != null;

        AttackStrength strength = null;
        AlertThreshold threshold = null;
        if (defined) {
            strength =
                    JobUtils.parseAttackStrength(
                            definition.getDefaultStrength(), jobName, progress);
            if (strength != null) {
                progress.info(
                        Constant.messages.getString(
                                "automation.info.ascan.setdefstrength", jobName, strength.name()));
            }
            threshold =
                    JobUtils.parseAlertThreshold(
                            definition.getDefaultThreshold(), jobName, progress);
            if (threshold != null) {
                progress.info(
                        Constant.messages.getString(
                                "automation.info.ascan.setdefthreshold",
                                jobName,
                                threshold.name()));
            }
        }

        try {
            GspmPolicyOperations.addPolicy(
                    registry, policyName, GLOBAL_SCAN_POLICY_TOOL, threshold, strength);
        } catch (IllegalStateException e) {
            progress.warn(
                    Constant.messages.getString(
                            "automation.error.scanpolicy.exists", jobName, policyName));
            return;
        } catch (RuntimeException e) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.scanpolicy.gspm.failed",
                            jobName,
                            policyName,
                            e.getMessage()));
            LOGGER.error(e.getMessage(), e);
            return;
        }
        if (!defined) {
            return;
        }

        for (Rule rule : definition.getEffectiveRules()) {
            try {
                configureRule(registry, policyName, rule, jobName, progress);
            } catch (IllegalArgumentException e) {
                // The rule does not exist.
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.ascan.rule.unknown",
                                jobName,
                                String.valueOf(rule.getId())));
            } catch (RuntimeException e) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.scanpolicy.gspm.rule.failed",
                                jobName,
                                String.valueOf(rule.getId()),
                                policyName,
                                e.getMessage()));
                LOGGER.error(e.getMessage(), e);
            }
        }
    }

    private static void configureRule(
            GspmRegistry registry,
            String policyName,
            Rule rule,
            String jobName,
            AutomationProgress progress) {
        String ruleId = String.valueOf(rule.getId());
        AttackStrength strength =
                JobUtils.parseAttackStrength(rule.getStrength(), jobName, progress);
        if (strength != null) {
            GspmPolicyOperations.setRuleStrength(
                    registry, policyName, GLOBAL_SCAN_POLICY_TOOL, rule.getId(), strength);
            // As when applying the policy to a scan, configuring the strength enables it.
            GspmPolicyOperations.setRulesEnabled(
                    registry, policyName, GLOBAL_SCAN_POLICY_TOOL, List.of(rule.getId()), true);
            progress.info(
                    Constant.messages.getString(
                            "automation.info.ascan.rule.setstrength",
                            jobName,
                            ruleId,
                            strength.name()));
        }
        AlertThreshold threshold =
                JobUtils.parseAlertThreshold(rule.getThreshold(), jobName, progress);
        if (threshold != null) {
            GspmPolicyOperations.setRuleThreshold(
                    registry, policyName, GLOBAL_SCAN_POLICY_TOOL, rule.getId(), threshold);
            progress.info(
                    Constant.messages.getString(
                            "automation.info.ascan.rule.setthreshold",
                            jobName,
                            ruleId,
                            threshold.name()));
        }
    }

    protected ScanPolicy getScanPolicy(AutomationProgress progress) {
        ScanPolicy scanPolicy =
                this.getData().getPolicyDefinition().getScanPolicy(this.getName(), progress);
        if (scanPolicy == null) {
            scanPolicy = new ScanPolicy();
        }
        scanPolicy.setName(this.getData().getParameters().getName());
        return scanPolicy;
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "automation.dialog.ascanpolicy.summary",
                JobUtils.unBox(this.getParameters().getName(), ""));
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return parameters;
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
        new ActiveScanPolicyJobDialog(this).setVisible(true);
    }

    @Getter
    public static class Data extends JobData {
        private final Parameters parameters;
        private final PolicyDefinition policyDefinition;

        public Data(AutomationJob job, Parameters parameters, PolicyDefinition policyDefinition) {
            super(job);
            this.parameters = parameters;
            this.policyDefinition = policyDefinition;
        }
    }

    @Getter
    @Setter
    public static class Parameters extends AutomationData {
        private String name;
    }
}
