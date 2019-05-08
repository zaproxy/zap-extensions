/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.bugtracker;

import org.zaproxy.zap.utils.Enableable;

class BugTrackerBugzillaConfigParams extends Enableable {

    private String username;
    private String password;
    private String bugzillaUrl;

    public BugTrackerBugzillaConfigParams() {
        this("", "", "");
    }

    public BugTrackerBugzillaConfigParams(String username, String password, String bugzillaUrl) {
        this.username = username;
        this.password = password;
        this.bugzillaUrl = bugzillaUrl;
    }

    public BugTrackerBugzillaConfigParams(BugTrackerBugzillaConfigParams config) {
        this(config.username, config.password, config.bugzillaUrl);
    }

    public String getName() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getBugzillaUrl() {
        return bugzillaUrl;
    }

    public void setName(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setBugzillaUrl(String bugzillaUrl) {
        this.bugzillaUrl = bugzillaUrl;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((password == null) ? 0 : password.hashCode());
        result = prime * result + ((bugzillaUrl == null) ? 0 : bugzillaUrl.hashCode());
        result = prime * result + ((username == null) ? 0 : username.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        BugTrackerBugzillaConfigParams other = (BugTrackerBugzillaConfigParams) obj;
        if (username == null) {
            if (other.username != null) {
                return false;
            }
        } else if (!username.equals(other.username)) {
            return false;
        }
        if (password == null) {
            if (other.password != null) {
                return false;
            }
        } else if (!password.equals(other.password)) {
            return false;
        }
        if (bugzillaUrl == null) {
            if (other.bugzillaUrl != null) {
                return false;
            }
        } else if (!bugzillaUrl.equals(other.bugzillaUrl)) {
            return false;
        }
        return true;
    }
}
