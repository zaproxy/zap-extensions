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
package org.zaproxy.zap.extension.wappalyzer.automation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.extension.wappalyzer.ApplicationMatch;
import org.zaproxy.zap.extension.wappalyzer.ExtensionWappalyzer;
import org.zaproxy.zap.extension.wappalyzer.TechTableModel;

public class WappalyzerJobResultData extends JobResultData {

    public static final String DATA_KEY = "wappalyzerData";

    private Map<String, List<TechnologyData>> siteTechMap = new HashMap<>();

    public WappalyzerJobResultData(String jobName) {
        super(jobName);

        ExtensionWappalyzer ext =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionWappalyzer.class);

        for (String site : ext.getSites()) {
            List<TechnologyData> techList = new ArrayList<>();
            TechTableModel model = ext.getTechModelForSite(site);
            for (ApplicationMatch appMatch : model.getApps()) {
                techList.add(new TechnologyData(appMatch));
            }
            siteTechMap.put(site, techList);
        }
    }

    public List<TechnologyData> getTechnologyForSite(String site) {
        List<TechnologyData> data = this.siteTechMap.get(site);
        if (data == null) {
            // XXX Do not use Collections.emptyList() breaks when running with Java 17, i.e.:
            // Unable to make public int java.util.Collections$EmptyList.size() accessible:
            // module java.base does not "opens java.util" to unnamed module @556150d9
            return new ArrayList<>(0);
        }
        return data;
    }

    public Set<String> getAllSites() {
        return this.siteTechMap.keySet();
    }

    @Override
    public String getKey() {
        return DATA_KEY;
    }

    public static class TechnologyData {
        private final String name;
        private final String description;
        private final String version;
        private final List<String> categories;
        private final String website;
        private final List<String> implies;
        private final String cpe;

        public TechnologyData(ApplicationMatch appMatch) {
            name = appMatch.getApplication().getName();
            description = appMatch.getApplication().getDescription();
            version = appMatch.getVersion();
            website = appMatch.getApplication().getWebsite();
            categories = appMatch.getApplication().getCategories();
            implies = appMatch.getApplication().getImplies();
            cpe = appMatch.getApplication().getCpe();
        }

        public String getName() {
            return name;
        }

        public String getDescription() {
            return description;
        }

        public String getVersion() {
            return version;
        }

        public List<String> getCategories() {
            return categories;
        }

        public String getWebsite() {
            return website;
        }

        public List<String> getImplies() {
            return implies;
        }

        public String getCpe() {
            return cpe;
        }
    }
}
