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
package org.zaproxy.zap.extension.sequence.automation;

import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.extension.sequence.StdActiveScanRunner.SequenceStepData;

@Getter
public class SequenceAScanJobResultData extends JobResultData {

    public static final String KEY = "seqAScanData";

    private List<SequenceData> seqData = new ArrayList<>();

    public SequenceAScanJobResultData(String jobName) {
        super(jobName);
    }

    public void addSequenceData(String sequenceName, List<SequenceStepData> steps) {
        seqData.add(new SequenceData(sequenceName, steps));
    }

    @Override
    public String getKey() {
        return KEY;
    }

    @Getter
    public static class SequenceData {
        private String sequenceName;
        private List<SequenceStepData> steps;

        public SequenceData(String sequenceName, List<SequenceStepData> steps) {
            this.sequenceName = sequenceName;
            this.steps = steps;
        }
    }
}
