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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.CommandLine;

public class AutomationProgress {

    private List<String> errors = new ArrayList<>();
    private List<String> warnings = new ArrayList<>();
    private List<String> infos = new ArrayList<>();
    private boolean outputToStdout = false;
    private Map<String, JobResultData> jobResultDataMap = new HashMap<>();

    public void error(String error) {
        this.errors.add(error);
        if (outputToStdout) {
            CommandLine.error(error);
        }
    }

    public void warn(String warning) {
        this.warnings.add(warning);
        if (outputToStdout) {
            CommandLine.info(warning);
        }
    }

    public void info(String info) {
        this.infos.add(info);
        if (outputToStdout) {
            CommandLine.info(info);
        }
    }

    public List<String> getErrors() {
        return errors;
    }

    public List<String> getWarnings() {
        return warnings;
    }

    public List<String> getInfos() {
        return infos;
    }

    public boolean hasErrors() {
        return errors.size() > 0;
    }

    public boolean hasWarnings() {
        return warnings.size() > 0;
    }

    public boolean isOutputToStdout() {
        return outputToStdout;
    }

    public void setOutputToStdout(boolean outputToStdout) {
        this.outputToStdout = outputToStdout;
    }

    public void addJobResultData(JobResultData data) {
        this.jobResultDataMap.put(data.getKey(), data);
    }

    public void addJobResultData(List<JobResultData> list) {
        for (JobResultData data : list) {
            this.jobResultDataMap.put(data.getKey(), data);
        }
    }

    public JobResultData getJobResultData(String key) {
        return this.jobResultDataMap.get(key);
    }

    public Collection<JobResultData> getAllJobResultData() {
        return this.jobResultDataMap.values();
    }
}
