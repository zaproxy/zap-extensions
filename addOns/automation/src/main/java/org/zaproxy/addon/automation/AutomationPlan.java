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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.yaml.snakeyaml.Yaml;

public class AutomationPlan {

    private static int nextId = 0;

    private File file;
    private AutomationProgress progress;
    private AutomationEnvironment env;
    private List<AutomationJob> jobs;
    private final int id;

    public AutomationPlan(ExtensionAutomation ext, File file)
            throws FileNotFoundException, IOException {
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
                        job.verifyJobSpecificData(progress);
                        job.setPlan(this);
                        jobs.add(job);

                        job.addTests(jobData.get("tests"), progress);
                    } catch (AutomationJobException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
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
        jobs.stream().forEach(j -> j.setPlan(this));
    }

    public AutomationProgress getProgress() {
        return progress;
    }

    /** This will create a new AutomationProgress object so the old one will no longer be updated */
    public void resetProgress() {
        progress = new AutomationProgress();
        jobs.stream().forEach(j -> j.reset());
    }

    public AutomationEnvironment getEnv() {
        return env;
    }

    public List<AutomationJob> getJobs() {
        return jobs;
    }

    public int getJobsCount() {
        return jobs.size();
    }

    public int getJobId(AutomationJob job) {
        return jobs.indexOf(job);
    }

    public AutomationJob getJob(int index) {
        return jobs.get(index);
    }

    public int getId() {
        return id;
    }

    public void save() {
        // TODO WIP
        if (file == null) {
            System.out.println("AutomationPlan " + id + " file null:(");
        } else {
            System.out.println("AutomationPlan " + id + " file " + file.getAbsolutePath());
        }
        System.out.println("... gotta start somewhere ... ");
        ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
        try {
            // System.out.println(objectMapper.writeValueAsString(this));

            Data data = new Data();
            data.setEnv(this.env.getData());
            for (AutomationJob job : this.jobs) {
                data.addJob(job.getData());
            }

            FilterProvider filters =
                    new SimpleFilterProvider()
                            .addFilter("ignoreDefaultFilter", new DefaultPropertyFilter());
            System.out.println(objectMapper.writer(filters).writeValueAsString(data));

            // System.out.println(objectMapper.writeValueAsString(data));

        } catch (JsonProcessingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
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
