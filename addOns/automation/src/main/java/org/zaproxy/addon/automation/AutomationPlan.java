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

import java.util.List;

public class AutomationPlan {

    private static int nextId = 0;

    private AutomationProgress progress;
    private AutomationEnvironment env;
    private List<AutomationJob> jobs;
    private final int id;

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
}
