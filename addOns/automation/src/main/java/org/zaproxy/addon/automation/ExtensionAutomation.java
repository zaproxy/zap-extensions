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

import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import javax.swing.Timer;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.parosproxy.paros.view.View;
import org.parosproxy.paros.view.WorkbenchPanel;
import org.zaproxy.addon.automation.gui.AutomationMovedStatusPanel;
import org.zaproxy.addon.automation.gui.AutomationOutputSource;
import org.zaproxy.addon.automation.gui.AutomationPanel;
import org.zaproxy.addon.automation.gui.OptionsPanel;
import org.zaproxy.addon.automation.jobs.ActiveScanConfigJob;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.ActiveScanPolicyJob;
import org.zaproxy.addon.automation.jobs.DelayJob;
import org.zaproxy.addon.automation.jobs.ExitStatusJob;
import org.zaproxy.addon.automation.jobs.ParamsJob;
import org.zaproxy.addon.automation.jobs.RequestorJob;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.ZAP.ProcessType;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.script.ScriptVars;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.utils.Stats;

public class ExtensionAutomation extends ExtensionAdaptor implements CommandLineListener {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionAutomation";

    // The i18n prefix
    public static final String PREFIX = "automation";

    public static final String RESOURCES_DIR = "/org/zaproxy/addon/automation/resources/";
    public static final int OK_EXIT_VALUE = 0;
    public static final int ERROR_EXIT_VALUE = 1;
    public static final int WARN_EXIT_VALUE = 2;

    protected static final String PLANS_RUN_STATS = "stats.auto.plans.run";
    protected static final String TOTAL_JOBS_RUN_STATS = "stats.auto.jobs.run";
    protected static final String JOBS_RUN_STATS_PREFIX = "stats.auto.job.";
    protected static final String JOBS_RUN_STATS_POSTFIX = ".run";
    protected static final String ERROR_COUNT_STATS = "stats.auto.errors";
    protected static final String WARNING_COUNT_STATS = "stats.auto.warnings";

    private static final String ZAP_AUTH_HEADER_VALUE = "ZAP_AUTH_HEADER_VALUE";
    private static final String ZAP_AUTH_HEADER = "ZAP_AUTH_HEADER";
    private static final String ZAP_AUTH_HEADER_SITE = "ZAP_AUTH_HEADER_SITE";

    private static final Logger LOGGER = LogManager.getLogger(ExtensionAutomation.class);

    private Map<String, AutomationJob> jobs = new HashMap<>();
    private SortedSet<AutomationJob> sortedJobs = new TreeSet<>();

    private OptionsPanel optionsPanel;
    private AutomationParam param;
    private LinkedHashMap<Integer, AutomationPlan> plans = new LinkedHashMap<>();
    private List<AutomationPlan> runningPlans = Collections.synchronizedList(new ArrayList<>());

    private CommandLineArgument[] arguments = new CommandLineArgument[5];
    private static final int ARG_AUTO_RUN_IDX = 0;
    private static final int ARG_AUTO_GEN_MIN_IDX = 1;
    private static final int ARG_AUTO_GEN_MAX_IDX = 2;
    private static final int ARG_AUTO_GEN_CONF_IDX = 3;
    private static final int ARG_AUTO_CHECK_IDX = 4;

    private AutomationPanel automationPanel;
    private AutomationOutputSource outputSource;
    private AutomationMovedStatusPanel movedStatusPanel;
    private final HierarchyListener movedStatusPanelHierarchyListener =
            this::movedStatusPanelHierarchyListener;

    private static Integer exitOverride;

    public ExtensionAutomation() {
        super(NAME);
        setI18nPrefix(PREFIX);

        // Instantiate early so its visible to potential consumers
        AutomationEventPublisher.getPublisher();
    }

    @SuppressWarnings("deprecation")
    @Override
    public void init() {
        super.init();

        registerAutomationJob(new org.zaproxy.addon.automation.jobs.AddOnJob());
        registerAutomationJob(new RequestorJob());
        registerAutomationJob(new DelayJob());
        registerAutomationJob(new ExitStatusJob());
        registerAutomationJob(
                new ActiveScanConfigJob(
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionActiveScan.class)));
        registerAutomationJob(new ActiveScanJob());
        registerAutomationJob(new ActiveScanPolicyJob());
        registerAutomationJob(new ParamsJob());
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addCommandLine(getCommandLineArguments());
        extensionHook.addOptionsParamSet(getParam());

        extensionHook.addApiImplementor(new AutomationAPI(this));

        if (hasView()) {
            getView().getOutputPanel().registerOutputSource(getOutputSource());
            extensionHook.getHookView().addWorkPanel(getAutomationPanel());
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());
            extensionHook.getHookView().addStatusPanel(getMovedStatusPanel());
            View.getSingleton()
                    .getWorkbench()
                    .getTabbedFull()
                    .addHierarchyListener(movedStatusPanelHierarchyListener);
        }

        extensionHook.addSessionListener(
                new SessionChangedListener() {

                    @Override
                    public void sessionChanged(Session session) {
                        // Work around for core bug - can be removed once the core is fixed and
                        // released
                        String authHeaderValueVar = System.getenv(ZAP_AUTH_HEADER_VALUE);
                        if (authHeaderValueVar != null && !authHeaderValueVar.isEmpty()) {
                            ScriptVars.setGlobalVar(ZAP_AUTH_HEADER_VALUE, authHeaderValueVar);
                        }

                        String authHeaderVar = System.getenv(ZAP_AUTH_HEADER);
                        if (authHeaderVar != null && !authHeaderVar.isEmpty()) {
                            ScriptVars.setGlobalVar(ZAP_AUTH_HEADER, authHeaderVar);
                        } else {
                            ScriptVars.setGlobalVar(ZAP_AUTH_HEADER, HttpHeader.AUTHORIZATION);
                        }

                        String authHeaderSiteVar = System.getenv(ZAP_AUTH_HEADER_SITE);
                        if (authHeaderSiteVar != null && !authHeaderSiteVar.isEmpty()) {
                            ScriptVars.setGlobalVar(ZAP_AUTH_HEADER_SITE, authHeaderSiteVar);
                        }
                    }

                    @Override
                    public void sessionAboutToChange(Session session) {
                        // Ignore
                    }

                    @Override
                    public void sessionScopeChanged(Session session) {
                        // Ignore
                    }

                    @Override
                    public void sessionModeChanged(Mode mode) {
                        // Ignore
                    }
                });
    }

    private OptionsPanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new OptionsPanel();
        }
        return optionsPanel;
    }

    @Override
    public void start() {
        if (hasView() && this.getParam().isOpenLastPlan()) {
            String path = getParam().getLastPlanPath();
            if (path != null) {
                File f = new File(path);
                if (f.canRead()) {
                    try {
                        getAutomationPanel().loadPlan(this.loadPlan(f));
                        getAutomationPanel().setTabFocus();
                    } catch (IOException e) {
                        LOGGER.debug(e.getMessage(), e);
                    }
                }
            }
        }
    }

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed
        // from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        ZAP.getEventBus().unregisterPublisher(AutomationEventPublisher.getPublisher());
        if (hasView()) {
            getView().getOutputPanel().unregisterOutputSource(getOutputSource());
            View.getSingleton()
                    .getWorkbench()
                    .getTabbedFull()
                    .removeHierarchyListener(movedStatusPanelHierarchyListener);
        }
    }

    @Override
    public List<String> getUnsavedResources() {
        if (this.hasView()) {
            return getAutomationPanel().getUnsavedPlans();
        }
        return Collections.emptyList();
    }

    private AutomationPanel getAutomationPanel() {
        if (automationPanel == null) {
            automationPanel = new AutomationPanel(this);
        }
        return automationPanel;
    }

    private AutomationMovedStatusPanel getMovedStatusPanel() {
        if (movedStatusPanel == null) {
            movedStatusPanel = new AutomationMovedStatusPanel(getAutomationPanel());
        }
        return movedStatusPanel;
    }

    private void movedStatusPanelHierarchyListener(HierarchyEvent e) {
        WorkbenchPanel workbench = View.getSingleton().getWorkbench();
        if ((e.getChangeFlags() & HierarchyEvent.DISPLAYABILITY_CHANGED) != 0) {
            if (workbench.getWorkbenchLayout() == WorkbenchPanel.Layout.FULL) {
                workbench.removePanel(getMovedStatusPanel(), WorkbenchPanel.PanelType.STATUS);
            } else if (workbench.getPanels(WorkbenchPanel.PanelType.STATUS).stream()
                    .noneMatch(panel -> panel instanceof AutomationMovedStatusPanel)) {
                workbench.addPanel(getMovedStatusPanel(), WorkbenchPanel.PanelType.STATUS);
            }
        }
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
            if (incAll) {
                fw.write(AutomationEnvironment.getTemplateFileDataMax());
            } else {
                fw.write(AutomationEnvironment.getTemplateFileDataMin());
            }

            jobs.values().stream()
                    .filter(job -> job.getClass().getAnnotation(Deprecated.class) == null)
                    .filter(Predicate.not(AutomationJob::isDataJob))
                    .sorted()
                    .forEach(
                            j -> {
                                try {
                                    String template =
                                            incAll
                                                    ? j.getTemplateDataMax()
                                                    : j.getTemplateDataMin();
                                    if (StringUtils.isBlank(template)) {
                                        return;
                                    }
                                    template = template.stripTrailing() + "\n\n";
                                    fw.write(template);
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

    private void setPlanFinished(AutomationPlan plan) {
        plan.getJobs().forEach(AutomationJob::planFinished);
        plan.setFinished(new Date());
        AutomationEventPublisher.publishEvent(
                AutomationEventPublisher.PLAN_FINISHED, plan, plan.getProgress().toMap());
        Stats.incCounter(ERROR_COUNT_STATS, plan.getProgress().getErrors().size());
        Stats.incCounter(WARNING_COUNT_STATS, plan.getProgress().getWarnings().size());
        runningPlans.remove(plan);
    }

    /**
     * Returns a list of currently running plans in the order they were started
     *
     * @return a list of currently running plans in the order they were started
     */
    public List<AutomationPlan> getRunningPlans() {
        return Collections.unmodifiableList(runningPlans);
    }

    public void stopPlan(AutomationPlan plan) {
        plan.stopPlan();
    }

    public AutomationProgress runPlan(AutomationPlan plan, boolean resetProgress) {
        runningPlans.add(plan);
        if (resetProgress) {
            plan.resetProgress();
        }

        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();

        plan.setStarted(new Date());
        plan.setFinished(null);

        AutomationEventPublisher.publishEvent(AutomationEventPublisher.PLAN_STARTED, plan, null);
        env.create(Model.getSingleton().getSession(), progress);

        AutomationEventPublisher.publishEvent(
                AutomationEventPublisher.PLAN_ENV_CREATED, plan, null);
        Stats.incCounter(PLANS_RUN_STATS);

        List<AutomationJob> jobsToRun = plan.getJobs();

        jobsToRun.forEach(AutomationJob::planStarted);

        if (progress.hasErrors() || env.isTimeToQuit()) {
            // If the environment reports an error then no point in continuing
            setPlanFinished(plan);
            return progress;
        }

        // Apply any configs
        Map<String, String> configs = env.getData().getConfigs();
        if (!configs.isEmpty()) {
            OptionsParam options = Model.getSingleton().getOptionsParam();
            Long errorCount = null;
            Long warnCount = null;
            ExtensionStats extStats =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionStats.class);
            InMemoryStats inMemoryStats = null;
            if (extStats != null) {
                inMemoryStats = extStats.getInMemoryStats();
                if (inMemoryStats != null) {
                    errorCount = inMemoryStats.getStat("stats.log.error");
                    warnCount = inMemoryStats.getStat("stats.log.warn");
                }
            }

            for (Entry<String, String> entry : configs.entrySet()) {
                Object current = options.getConfig().getProperty(entry.getKey());
                options.getConfig().setProperty(entry.getKey(), entry.getValue());
                Stats.incCounter("stats.auto.config." + entry.getKey());
                progress.info(
                        Constant.messages.getString(
                                "automation.info.configset",
                                entry.getKey(),
                                current,
                                entry.getValue()));
            }
            options.reloadConfigParamSets();
            Control.getSingleton().getExtensionLoader().optionsChangedAllPlugin(options);

            if (inMemoryStats != null) {
                // Check for any new warnings or errors
                if (ObjectUtils.compare(errorCount, inMemoryStats.getStat("stats.log.error"))
                        != 0) {
                    progress.error(
                            Constant.messages.getString("automation.env.error.config.error"));
                }
                if (ObjectUtils.compare(warnCount, inMemoryStats.getStat("stats.log.warn")) != 0) {
                    progress.warn(Constant.messages.getString("automation.env.error.config.warn"));
                }
            }
        }

        for (AutomationJob job : jobsToRun) {

            if ((plan.isStopping() || env.isTimeToQuit())
                    && (plan.isHardStopping() || !job.isAlwaysRun())) {
                continue;
            }

            if (!job.isEnabled()) {
                progress.info(
                        Constant.messages.getString("automation.info.jobdisabled", job.getType()));
                job.setStatus(AutomationJob.Status.NOT_ENABLED);
                continue;
            }

            job.applyParameters(progress);
            progress.info(Constant.messages.getString("automation.info.jobstart", job.getType()));
            job.setStatus(AutomationJob.Status.RUNNING);
            AutomationEventPublisher.publishEvent(AutomationEventPublisher.JOB_STARTED, job, null);
            job.setTimeStarted();
            Timer timer = null;
            if (View.isInitialised()) {
                timer = new Timer(1000, e -> getAutomationPanel().updateJob(job));
                timer.start();
            }
            try {
                job.runJob(env, progress);
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
                progress.error(
                        Constant.messages.getString(
                                "automation.error.unexpected.internal", e.getMessage()));
            }
            job.setTimeFinished();
            if (timer != null) {
                timer.stop();
            }
            Stats.incCounter(TOTAL_JOBS_RUN_STATS);
            Stats.incCounter(JOBS_RUN_STATS_PREFIX + job.getType() + JOBS_RUN_STATS_POSTFIX);
            job.logTestsToProgress(progress);
            job.setStatus(AutomationJob.Status.COMPLETED);
            AutomationEventPublisher.publishEvent(
                    AutomationEventPublisher.JOB_FINISHED,
                    job,
                    job.getPlan().getProgress().getJobResults(job).toMap());
            progress.info(
                    Constant.messages.getString(
                            "automation.info.jobend", job.getType(), job.getFormattedTimeTaken()));
            progress.addRunJob(job);
        }
        setPlanFinished(plan);
        return progress;
    }

    public void runPlanAsync(AutomationPlan plan) {
        new Thread(() -> this.runPlan(plan, true), "ZAP-Automation").start();
    }

    public AutomationPlan loadPlan(File f) throws IOException {
        return new AutomationPlan(this, f, false);
    }

    /**
     * Loads a plan from the given input stream.
     *
     * @param in the input stream with the plan in YAML format.
     * @return the plan.
     * @since 0.4.0
     */
    public AutomationPlan loadPlan(InputStream in) {
        return loadPlan(in, false);
    }

    public AutomationPlan loadPlan(InputStream in, boolean quiet) {
        return new AutomationPlan(this, in, quiet);
    }

    public void loadPlan(AutomationPlan plan, boolean setFocus, boolean run) {
        if (hasView()) {
            getAutomationPanel().loadPlan(plan);
            if (setFocus) {
                getAutomationPanel().setTabFocus();
            }
            if (run) {
                this.runPlanAsync(plan);
            }
        }
    }

    public AutomationJob getJobByEvent(Event e) {
        if (hasView()) {
            return getAutomationPanel().getJob(e);
        }
        return null;
    }

    public void registerPlan(AutomationPlan plan) {
        this.plans.put(plan.getId(), plan);
    }

    public void displayPlan(AutomationPlan plan) {
        if (this.hasView()) {
            this.getAutomationPanel().setCurrentPlan(plan);
        }
        registerPlan(plan);
    }

    public AutomationPlan getPlan(int planId) {
        return this.plans.get(planId);
    }

    /**
     * Load the automation plan defined by the given file, intended only to be used from the command
     * line.
     *
     * @param filename the name of the file
     * @param quiet if set then will not output info messages to the console
     * @return the automation progress
     */
    private AutomationPlan loadAutomationFile(String filename, boolean quiet) {
        File f = new File(filename);
        if (!f.exists() || !f.canRead()) {
            CommandLine.error(
                    Constant.messages.getString("automation.error.nofile", f.getAbsolutePath()));
            setExitStatus(ERROR_EXIT_VALUE, "no such file", false);
            return null;
        }
        try {
            return new AutomationPlan(this, f, quiet);
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            CommandLine.error(
                    Constant.messages.getString(
                            "automation.error.unexpected", f.getAbsolutePath(), e.getMessage()));
            setExitStatus(ERROR_EXIT_VALUE, "exception reading file", false);
            return null;
        }
    }

    /**
     * Run the automation plan defined by the given file, intended only to be used from the command
     * line.
     *
     * @param filename the name of the file
     * @return the automation progress
     */
    protected AutomationProgress runAutomationFile(String filename) {
        try {
            return this.runAutomationPlan(this.loadAutomationFile(filename, false));
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            File f = new File(filename);
            CommandLine.error(
                    Constant.messages.getString(
                            "automation.error.unexpected", f.getAbsolutePath(), e.getMessage()));
            return null;
        }
    }

    private AutomationProgress runAutomationPlan(AutomationPlan plan) {
        this.displayPlan(plan);
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

    public AutomationJob getAutomationJob(String type) {
        return jobs.get(type);
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
                        "-autorun <source>        "
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
        arguments[ARG_AUTO_CHECK_IDX] =
                new CommandLineArgument(
                        "-autocheck",
                        1,
                        null,
                        "",
                        "-autocheck <source>      "
                                + Constant.messages.getString("automation.cmdline.autocheck.help"));
        return arguments;
    }

    @Override
    public void execute(CommandLineArgument[] args) {
        if (arguments[ARG_AUTO_RUN_IDX].isEnabled()) {
            runPlanCommandLine(arguments[ARG_AUTO_RUN_IDX].getArguments().firstElement());
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
        if (arguments[ARG_AUTO_CHECK_IDX].isEnabled()) {
            checkPlanCommandLine(arguments[ARG_AUTO_CHECK_IDX].getArguments().firstElement());
        }
    }

    private AutomationPlan loadPlanCommandLine(String source, boolean quiet) {
        URI uri = createUri(source);
        if (uri != null) {
            try {
                HttpMessage message = new HttpMessage(uri);
                new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR).sendAndReceive(message);
                int statusCode = message.getResponseHeader().getStatusCode();
                if (statusCode != HttpStatusCode.OK) {
                    setExitStatus(
                            1,
                            "non-200 response (" + statusCode + ") for remote plan: " + source,
                            true);
                    return null;
                }

                return this.loadPlan(
                        new ByteArrayInputStream(message.getResponseBody().getBytes()), quiet);

            } catch (IOException e) {
                setExitStatus(1, "I/O error getting remote plan: " + e.getMessage(), true);
                return null;
            }
        } else {
            return loadAutomationFile(source, quiet);
        }
    }

    private void setExitStatus(AutomationProgress progress) {
        if (exitOverride != null) {
            setExitStatus(exitOverride, "set by user", false);
        } else if (progress == null || progress.hasErrors()) {
            setExitStatus(ERROR_EXIT_VALUE, "plan errors", false);
        } else if (progress.hasWarnings()) {
            setExitStatus(WARN_EXIT_VALUE, "plan warnings", false);
        }
    }

    private void runPlanCommandLine(String source) {
        AutomationPlan plan = loadPlanCommandLine(source, false);
        if (plan != null) {
            setExitStatus(runAutomationPlan(plan));
        }
    }

    protected AutomationProgress checkPlanCommandLine(String source) {
        AutomationPlan plan = loadPlanCommandLine(source, true);
        if (plan != null) {
            setExitStatus(plan.getProgress());
            return plan.getProgress();
        }
        return null;
    }

    public static Integer getExitOverride() {
        return exitOverride;
    }

    public static void setExitOverride(Integer exitOverride) {
        ExtensionAutomation.exitOverride = exitOverride;
    }

    private static URI createUri(String source) {
        try {
            new java.net.URI(source).toURL();
            URI uri = new URI(source, true);
            String scheme = uri.getScheme();
            if (HttpHeader.HTTP.equalsIgnoreCase(scheme)
                    || HttpHeader.HTTPS.equalsIgnoreCase(scheme)) {
                return uri;
            }
            LOGGER.debug("Skipping non-HTTP(S) URI, will attempt to run plan as file.");
        } catch (Exception e) {
            LOGGER.debug("Failed to parse {} as URI, attempting to run plan as file.", source, e);
        }
        return null;
    }

    private static void setExitStatus(int status, String logMessage, boolean error) {
        if (ProcessType.cmdline.equals(ZAP.getProcessType())) {
            String fullMessage =
                    "Automation Framework setting exit status to "
                            + status
                            + " due to "
                            + logMessage;
            if (error) {
                CommandLine.error(fullMessage);
            }
            Control.getSingleton().setExitStatus(status, fullMessage);
        }
    }

    @Override
    public List<String> getHandledExtensions() {
        return Collections.emptyList();
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

    @Override
    public String getUIName() {
        return Constant.messages.getString("automation.name");
    }

    public AutomationOutputSource getOutputSource() {
        if (outputSource == null) {
            outputSource =
                    new AutomationOutputSource(
                            Constant.messages.getString("automation.output.name"));
        }
        return outputSource;
    }
}
