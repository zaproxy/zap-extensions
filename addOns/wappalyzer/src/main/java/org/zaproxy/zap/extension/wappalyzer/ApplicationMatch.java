/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.wappalyzer;

import java.util.HashSet;
import java.util.Set;
import org.parosproxy.paros.Constant;

public class ApplicationMatch {

    private Application application;
    private Set<String> versions;

    public ApplicationMatch(Application application) {
        this.application = application;
        this.versions = new HashSet<>();
    }

    public Application getApplication() {
        return application;
    }

    public void addVersion(String version) {
        versions.add(version);
    }

    public String getVersion() {
        return String.join(Constant.messages.getString("wappalyzer.version.delimiter"), versions);
    }

    public Set<String> getVersions() {
        return versions;
    }
}
