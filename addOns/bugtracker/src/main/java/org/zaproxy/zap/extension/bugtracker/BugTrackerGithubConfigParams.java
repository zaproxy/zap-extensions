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

class BugTrackerGithubConfigParams extends Enableable {

    private String username;
    private String token;
    private String repoUrl;

    public BugTrackerGithubConfigParams() {
        this("", "", "");
    }

    public BugTrackerGithubConfigParams(String username, String token, String repoUrl) {
        this.username = username;
        this.token = token;
        this.repoUrl = repoUrl;
    }

    public BugTrackerGithubConfigParams(BugTrackerGithubConfigParams config) {
        this(config.username, config.token, config.repoUrl);
    }

    public String getName() {
        return username;
    }

    public String getToken() {
        return token;
    }

    public String getRepoUrl() {
        return repoUrl;
    }

    public void setName(String username) {
        this.username = username;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public void setRepoUrl(String repoUrl) {
        this.repoUrl = repoUrl;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((token == null) ? 0 : token.hashCode());
        result = prime * result + ((repoUrl == null) ? 0 : repoUrl.hashCode());
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
        BugTrackerGithubConfigParams other = (BugTrackerGithubConfigParams) obj;
        if (username == null) {
            if (other.username != null) {
                return false;
            }
        } else if (!username.equals(other.username)) {
            return false;
        }
        if (token == null) {
            if (other.token != null) {
                return false;
            }
        } else if (!token.equals(other.token)) {
            return false;
        }
        if (repoUrl == null) {
            if (other.repoUrl != null) {
                return false;
            }
        } else if (!repoUrl.equals(other.repoUrl)) {
            return false;
        }
        return true;
    }
}
