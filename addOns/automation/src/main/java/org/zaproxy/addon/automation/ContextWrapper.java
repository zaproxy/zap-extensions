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
import java.util.List;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.model.Context;

public class ContextWrapper {

    private Context context;

    private Data data;

    public ContextWrapper(Data data) {
        this.data = data;
    }

    // TODO remove, once tests fixed
    public ContextWrapper(Context context) {
        this.context = context;
        this.data = new Data();
    }

    public Context getContext() {
        return this.context;
    }

    public void addUrl(String url) {
        this.data.getUrls().add(url);
    }

    public List<String> getUrls() {
        return this.data.getUrls();
    }

    public Data getData() {
        return data;
    }

    public void setData(Data data) {
        this.data = data;
    }

    public void createContext(Session session) {
        Context oldContext = session.getContext(getData().getName());
        if (oldContext != null) {
            session.deleteContext(oldContext);
        }
        this.context = session.getNewContext(getData().getName());
        for (String url : getData().getUrls()) {
            this.context.addIncludeInContextRegex(url + ".*");
        }
        for (String path : getData().getIncludePaths()) {
            this.context.addIncludeInContextRegex(path);
        }
        this.context.setExcludeFromContextRegexs(getData().getExcludePaths());
    }

    public static class Data {
        private String name;
        private List<String> urls = new ArrayList<>();
        private List<String> includePaths;
        private List<String> excludePaths;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public List<String> getUrls() {
            return urls;
        }

        public void setUrls(List<String> urls) {
            this.urls = urls;
        }

        public List<String> getIncludePaths() {
            return includePaths;
        }

        public void setIncludePaths(List<String> includePaths) {
            this.includePaths = includePaths;
        }

        public List<String> getExcludePaths() {
            return excludePaths;
        }

        public void setExcludePaths(List<String> excludePaths) {
            this.excludePaths = excludePaths;
        }
    }
}
