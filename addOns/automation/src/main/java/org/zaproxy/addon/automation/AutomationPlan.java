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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ser.FilterProvider;
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.yaml.snakeyaml.Yaml;

public class AutomationPlan {

    private static int nextId = 0;

    private File file;
    private AutomationProgress progress;
    private AutomationEnvironment env;
    private List<AutomationJob> jobs;
    private final int id;
    private boolean changed = false;
    private Date started;
    private Date finished;

    private static final Logger LOG = LogManager.getLogger(AutomationPlan.class);

    public AutomationPlan() {
        super();
        this.progress = new AutomationProgress();
        this.env = new AutomationEnvironment(this.progress);
        this.jobs = new ArrayList<>();
        this.id = nextId++;
        env.setPlan(this);
    }

    public AutomationPlan(ExtensionAutomation ext, File file) throws IOException {
        super();
        this.id = nextId++;
        this.file = file;
        try (FileInputStream is = new FileInputStream(file)) {
            Yaml yaml = new Yaml();
            LinkedHashMap<?, ?> data = yaml.load(is);
            LinkedHashMap<?, ?> envData = (LinkedHashMap<?, ?>) data.get("env");
            ArrayList<?> jobsData = (ArrayList<?>) data.get("jobs");

            progress = new AutomationProgress();
            env = new AutomationEnvironment(envData, progress);
            env.setPlan(this);

            jobs = new ArrayList<>();

            for (Object jobObj : jobsData) {
                if (!(jobObj instanceof LinkedHashMap<?, ?>)) {
                    progress.error(
                            Constant.messages.getString("automation.error.job.data", jobObj));
                    continue;
                }
                LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) jobObj;

                Object jobType = jobData.get("type");
                if (jobType == null) {
                    progress.error(
                            Constant.messages.getString("automation.error.job.notype", jobType));
                    continue;
                }
                AutomationJob job = ext.getAutomationJob(jobType.toString());
                if (job != null) {
                    try {
                        job = job.newJob();
                        Object jobName = jobData.get("name");
                        if (jobName != null) {
                            if (jobName instanceof String) {
                                job.setName((String) jobName);
                            } else {
                                progress.warn(
                                        Constant.messages.getString(
                                                "automation.error.job.name", jobName));
                            }
                        }

                        Object paramsObj = jobData.get("parameters");
                        if (paramsObj != null && !(paramsObj instanceof LinkedHashMap<?, ?>)) {
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.job.data", paramsObj));
                            continue;
                        }
                        job.setEnv(env);
                        job.setJobData(jobData);
                        job.verifyParameters(progress);
                        job.setPlan(this);
                        jobs.add(job);

                        job.addTests(jobData.get("tests"), progress);
                    } catch (AutomationJobException e) {
                        LOG.debug(e.getMessage(), e);
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.job.internal", jobType, e.getMessage()));
                    }
                } else {
                    progress.error(
                            Constant.messages.getString("automation.error.job.unknown", jobType));
                }
            }
        }
    }

    public AutomationPlan(
            AutomationEnvironment env, List<AutomationJob> jobs, AutomationProgress progress) {
        super();
        this.progress = progress;
        this.env = env;
        this.jobs = jobs;
        this.id = nextId++;
        env.setPlan(this);
        jobs.stream().forEach(j -> j.setPlan(this));
    }

    public AutomationProgress getProgress() {
        return progress;
    }

    /** This will create a new AutomationProgress object so the old one will no longer be updated */
    public void resetProgress() {
        progress = new AutomationProgress();
        this.getEnv().setProgress(progress);
        jobs.stream().forEach(AutomationJob::reset);
        started = null;
        finished = null;
    }

    public AutomationEnvironment getEnv() {
        return env;
    }

    public List<AutomationJob> getJobs() {
        return jobs;
    }

    public void addJob(AutomationJob job) {
        job.setPlan(this);
        job.setEnv(this.getEnv());
        try {
            for (AutomationJob j : jobs) {
                if (job.getOrder().compareTo(j.getOrder()) < 0) {
                    jobs.add(this.getJobIndex(j), job);
                    return;
                }
            }
            jobs.add(job);
        } finally {
            this.changed = true;
            AutomationEventPublisher.publishEvent(AutomationEventPublisher.JOB_ADDED, job, null);
        }
    }

    public boolean removeJob(AutomationJob job) {
        boolean result = this.jobs.remove(job);
        if (result) {
            AutomationEventPublisher.publishEvent(AutomationEventPublisher.JOB_REMOVED, job, null);
            this.changed = true;
        }
        return result;
    }

    public int getJobsCount() {
        return jobs.size();
    }

    public int getJobIndex(AutomationJob job) {
        return jobs.indexOf(job);
    }

    public AutomationJob getJob(int index) {
        return jobs.get(index);
    }

    public boolean moveJobUp(AutomationJob job) {
        int index = this.getJobIndex(job);
        if (index <= 0) {
            return false;
        }
        jobs.remove(index);
        jobs.add(index - 1, job);
        return true;
    }

    public boolean moveJobDown(AutomationJob job) {
        int index = this.getJobIndex(job);
        if (index == jobs.size() - 1) {
            return false;
        }
        jobs.remove(index);
        jobs.add(index + 1, job);
        return true;
    }

    public int getId() {
        return id;
    }

    public File getFile() {
        return file;
    }

    public void setFile(File file) {
        this.file = file;
    }

    public boolean isChanged() {
        return changed;
    }

    public void setChanged() {
        if (!changed) {
            AutomationEventPublisher.publishEvent(
                    AutomationEventPublisher.PLAN_CHANGED, this, null);
        }
        this.changed = true;
    }

    void setStarted(Date started) {
        this.started = started;
    }

    void setFinished(Date finished) {
        this.finished = finished;
    }

    public Date getStarted() {
        return started;
    }

    public Date getFinished() {
        return finished;
    }

    public boolean save() throws FileNotFoundException, JsonProcessingException {
        if (file == null) {
            LOG.error("Cannot save plan as it has no file set");
            return false;
        }
        LOG.debug("Writing plan to {}", file.getAbsolutePath());
        ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
        try (PrintWriter writer = new PrintWriter(file)) {
            Data data = new Data();
            data.setEnv(this.env.getData());
            for (AutomationJob job : this.jobs) {
                data.addJob(job.getData());
            }

            FilterProvider filters =
                    new SimpleFilterProvider()
                            .addFilter("ignoreDefaultFilter", new DefaultPropertyFilter());
            writer.println(objectMapper.writer(filters).writeValueAsString(data));
        }
        this.changed = false;
        AutomationEventPublisher.publishEvent(AutomationEventPublisher.PLAN_SAVED, this, null);
        return true;
    }

    public static class Data {
        private AutomationEnvironment.Data env;

        private List<AutomationData> jobs = new ArrayList<>();

        public AutomationEnvironment.Data getEnv() {
            return env;
        }

        public void setEnv(AutomationEnvironment.Data env) {
            this.env = env;
        }

        public List<AutomationData> getJobs() {
            return jobs;
        }

        public void addJob(AutomationData job) {
            if (job != null) {
                this.jobs.add(job);
            }
        }
    }
}
