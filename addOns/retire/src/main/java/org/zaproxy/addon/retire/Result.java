/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.retire;

import java.util.Collections;
import java.util.Set;
import org.zaproxy.addon.retire.model.Repo.VulnerabilityData;

public class Result {

    VulnerabilityData information;
    String version;
    String filename;
    String evidence;
    String otherinfo;

    public Result(
            final String filename,
            final String version,
            final VulnerabilityData info,
            String evidence) {
        this.filename = filename;
        this.version = version;
        this.information = info;
        this.evidence = evidence;
    }

    public VulnerabilityData getInformation() {
        return information;
    }

    public String getVersion() {
        return version;
    }

    public String getFilename() {
        return filename;
    }

    public String getEvidence() {
        return evidence;
    }

    public String getOtherinfo() {
        return otherinfo;
    }

    public void setOtherinfo(String otherinfo) {
        this.otherinfo = otherinfo;
    }

    public boolean hasOtherInfo() {
        return otherinfo != null && !otherinfo.isEmpty();
    }

    public Set<String> getCves() {
        if (information.isEmpty() || information.getCves().isEmpty()) {
            return Collections.emptySet();
        }
        return information.getCves();
    }
}
