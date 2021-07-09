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
package org.zaproxy.addon.automation;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.swing.ImageIcon;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.gui.AutomationPanel;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.AddOnJob;
import org.zaproxy.addon.automation.jobs.ParamsJob;
import org.zaproxy.addon.automation.jobs.PassiveScanConfigJob;
import org.zaproxy.addon.automation.jobs.PassiveScanWaitJob;
import org.zaproxy.addon.automation.jobs.RequestorJob;
import org.zaproxy.addon.automation.jobs.SpiderJob;

public class ExtensionAutomation extends ExtensionAdaptor implements CommandLineListener {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionAutomation";

    // The i18n prefix
    public static final String PREFIX = "automation";

    private static final String RESOURCES_DIR = "/org/zaproxy/addon/automation/resources/";

    public static final ImageIcon ICON =
            new ImageIcon(ExtensionAutomation.class.getResource(RESOURCES_DIR + "robot.png"));

    private static final Logger LOG = LogManager.getLogger(ExtensionAutomation.class);

    private Map<String, AutomationJob> jobs = new HashMap<>();
    private SortedSet<AutomationJob> sortedJobs = new TreeSet<>();

    private AutomationParam param;
    private LinkedHashMap<Integer, AutomationPlan> plans = new LinkedHashMap<>();

    private CommandLineArgument[] arguments = new CommandLineArgument[4];
    private static final int ARG_AUTO_RUN_IDX = 0;
    private static final int ARG_AUTO_GEN_MIN_IDX = 1;
    private static final int ARG_AUTO_GEN_MAX_IDX = 2;
    private static final int ARG_AUTO_GEN_CONF_IDX = 3;

    private AutomationPanel automationPanel;

    public ExtensionAutomation() {
        super(NAME);
        setI18nPrefix(PREFIX);

        this.registerAutomationJob(new AddOnJob());
        this.registerAutomationJob(new PassiveScanConfigJob());
        this.registerAutomationJob(new RequestorJob());
        this.registerAutomationJob(new PassiveScanWaitJob());
        this.registerAutomationJob(new SpiderJob());
        this.registerAutomationJob(new ActiveScanJob());
        this.registerAutomationJob(new ParamsJob());
        // Instantiate early so its visible to potential consumers
        AutomationEventPublisher.getPublisher();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addCommandLine(getCommandLineArguments());
        extensionHook.addOptionsParamSet(getParam());

        if (getView() != null) {
            extensionHook.getHookView().addStatusPanel(getAutomationPanel());
        }
    }

    @Override
    public void optionsLoaded() {}

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed
        // from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();
    }

    private AutomationPanel getAutomationPanel() {
        if (automationPanel == null) {
            automationPanel = new AutomationPanel(this);
        }
        return automationPanel;
    }

    public void registerAutomationJob(AutomationJob job) {
        this.jobs.put(job.getType(), job);
        this.sortedJobs.add(job);
    }

    public void unregisterAutomationJob(AutomationJob job) {
        this.jobs.remove(job.getType());
        this.sortedJobs.remove(job);
    }

    public void generateConfigFile(String filename) {
        File f = new File(filename);
        try (FileWriter fw = new FileWriter(f)) {
            fw.write(AutomationEnvironment.getConfigFileData());

            this.sortedJobs.forEach(
                    j -> {
                        try {
                            if (!j.isDataJob()) {
                                fw.write(j.getConfigFileData());
                                fw.write("\n");
                            }
                        } catch (IOException e) {
                            CommandLine.error(
                                    Constant.messages.getString(
                                            "automation.error.write", f.getAbsolutePath()),
                                    e);
                        }
                    });

        } catch (IOException e) {
            CommandLine.error(
                    Constant.messages.getString("automation.error.write", f.getAbsolutePath()), e);
        }
    }

    public void generateTemplateFile(String filename, boolean incAll) {
        File f = new File(filename);
        CommandLine.info(
                Constant.messages.getString(
                        "automation.cmdline.out.template", f.getAbsolutePath()));
        try (FileWriter fw = new FileWriter(f)) {
            fw.write(AutomationEnvironment.getTemplateFileData());

            jobs.values().stream()
                    .sorted()
                    .forEach(
                            j -> {
                                try {
                                    if (incAll) {
                                        fw.write(j.getTemplateDataMax());
                                    } else {
                                        fw.write(j.getTemplateDataMin());
                                    }
                                } catch (Exception e) {
                                    CommandLine.error(
                                            Constant.messages.getString(
                                                    "automation.error.job.template", j.getType()),
                                            e);
                                }
                            });

        } catch (IOException e) {
            CommandLine.error(
                    Constant.messages.getString("automation.error.write", f.getAbsolutePath()), e);
        }
    }

    public AutomationProgress runPlan(AutomationPlan plan, boolean resetProgress)
            throws AutomationJobException {
        if (resetProgress) {
            plan.resetProgress();
        }
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();

        AutomationEventPublisher.publishEvent(AutomationEventPublisher.PLAN_STARTED, plan, null);
        env.create(Model.getSingleton().getSession(), progress);

        if (env.isTimeToQuit()) {
            AutomationEventPublisher.publishEvent(
                    AutomationEventPublisher.PLAN_FINISHED, plan, plan.getProgress().toMap());
            return progress;
        }
        AutomationEventPublisher.publishEvent(
                AutomationEventPublisher.PLAN_ENV_CREATED, plan, null);

        List<AutomationJob> jobsToRun = plan.getJobs();

        for (AutomationJob job : jobsToRun) {
            job.applyParameters(progress);
            progress.info(Constant.messages.getString("automation.info.jobstart", job.getType()));
            job.setStatus(AutomationJob.Status.RUNNING);
            AutomationEventPublisher.publishEvent(AutomationEventPublisher.JOB_STARTED, job, null);
            job.runJob(env, progress);
            job.logTestsToProgress(progress);
            job.setStatus(AutomationJob.Status.COMPLETED);
            AutomationEventPublisher.publishEvent(
                    AutomationEventPublisher.JOB_FINISHED,
                    job,
                    job.getPlan().getProgress().getJobResults(job).toMap());
            progress.info(Constant.messages.getString("automation.info.jobend", job.getType()));
            progress.addRunJob(job);
            if (env.isTimeToQuit()) {
                break;
            }
        }

        AutomationEventPublisher.publishEvent(
                AutomationEventPublisher.PLAN_FINISHED, plan, plan.getProgress().toMap());
        return progress;
    }

    public AutomationPlan loadPlan(File f)
            throws AutomationJobException, FileNotFoundException, IOException {
        try (FileInputStream is = new FileInputStream(f)) {
            return this.loadPlan(is);
        }
    }

    public AutomationPlan loadPlan(InputStream in) throws AutomationJobException {
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(in);
        LinkedHashMap<?, ?> envData = (LinkedHashMap<?, ?>) data.get("env");
        ArrayList<?> jobsData = (ArrayList<?>) data.get("jobs");

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(envData, progress);

        List<AutomationJob> jobsToRun = new ArrayList<>();

        for (Object jobObj : jobsData) {
            if (!(jobObj instanceof LinkedHashMap<?, ?>)) {
                progress.error(Constant.messages.getString("automation.error.job.data", jobObj));
                continue;
            }
            LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) jobObj;

            Object jobType = jobData.get("type");
            if (jobType == null) {
                progress.error(Constant.messages.getString("automation.error.job.notype", jobType));
                continue;
            }
            AutomationJob job = jobs.get(jobType);
            if (job != null) {
                job = job.newJob();
                Object jobName = jobData.get("name");
                if (jobName != null) {
                    if (jobName instanceof String) {
                        job.setName((String) jobName);
                    } else {
                        progress.warn(
                                Constant.messages.getString("automation.error.job.name", jobName));
                    }
                }

                Object paramsObj = jobData.get("parameters");
                if (paramsObj != null && !(paramsObj instanceof LinkedHashMap<?, ?>)) {
                    progress.error(
                            Constant.messages.getString("automation.error.job.data", paramsObj));
                    continue;
                }
                job.setEnv(env);
                job.setJobData(jobData);
                job.verifyParameters(progress);
                job.verifyJobSpecificData(progress);
                jobsToRun.add(job);

                job.addTests(jobData.get("tests"), progress);
            } else {
                progress.error(
                        Constant.messages.getString("automation.error.job.unknown", jobType));
            }
        }

        return new AutomationPlan(env, jobsToRun, progress);
    }

    public void registerPlan(AutomationPlan plan) {
        this.plans.put(plan.getId(), plan);
    }

    public AutomationPlan getPlan(int planId) {
        return this.plans.get(planId);
    }

    /**
     * Run the automation plan define by the given file, intended only to be used from the command
     * line
     *
     * @param filename the name of the file
     * @return the automation progress
     */
    protected AutomationProgress runAutomationFile(String filename) {
        File f = new File(filename);
        if (!f.exists() || !f.canRead()) {
            CommandLine.error(
                    Constant.messages.getString("automation.error.nofile", f.getAbsolutePath()));
            return null;
        }
        try (FileInputStream is = new FileInputStream(f)) {
            AutomationPlan plan = this.loadPlan(is);
            if (View.isInitialised()) {
                this.getAutomationPanel().setCurrentPlan(plan);
            }
            this.runPlan(plan, false);
            AutomationProgress progress = plan.getProgress();

            if (progress.hasErrors()) {
                CommandLine.info(Constant.messages.getString("automation.out.title.fail"));
                for (String str : progress.getErrors()) {
                    CommandLine.info(Constant.messages.getString("automation.out.info", str));
                }
            }
            if (progress.hasWarnings()) {
                CommandLine.info(Constant.messages.getString("automation.out.title.warn"));
                for (String str : progress.getWarnings()) {
                    CommandLine.info(Constant.messages.getString("automation.out.info", str));
                }
            }

            if (!progress.hasErrors() && !progress.hasWarnings()) {
                CommandLine.info(Constant.messages.getString("automation.out.title.good"));
            }
            return progress;

        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            CommandLine.error(
                    Constant.messages.getString(
                            "automation.error.unexpected", f.getAbsolutePath(), e.getMessage()));
            return null;
        }
    }

    public static String getResourceAsString(String name) {
        try (InputStream in = ExtensionAutomation.class.getResourceAsStream(RESOURCES_DIR + name)) {
            return new BufferedReader(new InputStreamReader(in))
                            .lines()
                            .collect(Collectors.joining("\n"))
                    + "\n";
        } catch (Exception e) {
            CommandLine.error(
                    Constant.messages.getString("automation.error.nofile", RESOURCES_DIR + name));
        }
        return "";
    }

    public Map<String, AutomationJob> getAutomationJobs() {
        return Collections.unmodifiableMap(jobs);
    }

    public List<JobResultData> getJobResultData() {
        List<JobResultData> list = new ArrayList<>();
        for (AutomationJob job : jobs.values()) {
            list.addAll(job.getJobResultData());
        }
        return list;
    }

    public AutomationParam getParam() {
        if (param == null) {
            param = new AutomationParam();
        }
        return param;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    protected CommandLineArgument[] getCommandLineArguments() {
        arguments[ARG_AUTO_RUN_IDX] =
                new CommandLineArgument(
                        "-autorun",
                        1,
                        null,
                        "",
                        "-autorun <filename>      "
                                + Constant.messages.getString("automation.cmdline.autorun.help"));
        arguments[ARG_AUTO_GEN_MIN_IDX] =
                new CommandLineArgument(
                        "-autogenmin",
                        1,
                        null,
                        "",
                        "-autogenmin <filename>   "
                                + Constant.messages.getString(
                                        "automation.cmdline.autogenmin.help"));
        arguments[ARG_AUTO_GEN_MAX_IDX] =
                new CommandLineArgument(
                        "-autogenmax",
                        1,
                        null,
                        "",
                        "-autogenmax <filename>   "
                                + Constant.messages.getString(
                                        "automation.cmdline.autogenmax.help"));
        arguments[ARG_AUTO_GEN_CONF_IDX] =
                new CommandLineArgument(
                        "-autogenconf",
                        1,
                        null,
                        "",
                        "-autogenconf <filename>  "
                                + Constant.messages.getString(
                                        "automation.cmdline.autogenconf.help"));
        return arguments;
    }

    @Override
    public void execute(CommandLineArgument[] args) {
        if (arguments[ARG_AUTO_RUN_IDX].isEnabled()) {
            runAutomationFile(arguments[ARG_AUTO_RUN_IDX].getArguments().firstElement());
        }
        if (arguments[ARG_AUTO_GEN_MIN_IDX].isEnabled()) {
            generateTemplateFile(
                    arguments[ARG_AUTO_GEN_MIN_IDX].getArguments().firstElement(), false);
        }
        if (arguments[ARG_AUTO_GEN_MAX_IDX].isEnabled()) {
            generateTemplateFile(
                    arguments[ARG_AUTO_GEN_MAX_IDX].getArguments().firstElement(), true);
        }
        if (arguments[ARG_AUTO_GEN_CONF_IDX].isEnabled()) {
            generateConfigFile(arguments[ARG_AUTO_GEN_CONF_IDX].getArguments().firstElement());
        }
    }

    @Override
    public List<String> getHandledExtensions() {
        return null;
    }

    @Override
    public boolean handleFile(File file) {
        // Not supported
        return false;
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }
}
