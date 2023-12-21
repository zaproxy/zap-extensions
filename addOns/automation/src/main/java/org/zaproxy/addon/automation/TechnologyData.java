/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import java.util.Map;
import java.util.Map.Entry;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.TechSet;

public class TechnologyData extends AutomationData {

    private static final String INCLUDE_FIELD = "include";
    private static final String EXCLUDE_FIELD = "exclude";

    private List<String> exclude;
    private List<String> include;

    public TechnologyData() {
        exclude = new ArrayList<>();
        include = new ArrayList<>();
    }

    public TechnologyData(TechSet techSet) {
        if (techSet == null) {
            // Should only happen in tests
            techSet = new TechSet();
        }
        this.setExclude(techSet);
    }

    public TechnologyData(Context context) {
        this(context.getTechSet());
    }

    public void initContextTechnology(Context context, AutomationProgress progress) {
        context.setTechSet(TechnologyUtils.getTechSet(this));
    }

    public TechnologyData(Object data, AutomationProgress progress) {
        this();
        if (!(data instanceof Map)) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.context.badtech", data.getClass().getSimpleName()));
        } else {
            Map<?, ?> dataMap = (Map<?, ?>) data;

            for (Entry<?, ?> cdata : dataMap.entrySet()) {
                if (EXCLUDE_FIELD.equals(cdata.getKey().toString())) {
                    readTechs(exclude, cdata, progress, EXCLUDE_FIELD);
                } else if (INCLUDE_FIELD.equals(cdata.getKey().toString())) {
                    readTechs(include, cdata, progress, INCLUDE_FIELD);
                } else {
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.options.unknown",
                                    AutomationEnvironment.AUTOMATION_CONTEXT_NAME,
                                    cdata.getKey().toString()));
                }
            }
        }
    }

    private static void readTechs(
            List<String> into, Entry<?, ?> data, AutomationProgress progress, String field) {
        Object value = data.getValue();
        if (value == null) {
            return;
        }

        if (!(value instanceof List)) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.context.badtechtype",
                            field,
                            value.getClass().getSimpleName()));
            return;
        }

        List<?> urlList = (List<?>) value;
        for (Object urlObj : urlList) {
            String techName = urlObj.toString();
            into.add(techName);
            // Check it exists
            TechnologyUtils.getTech(techName, progress);
        }
    }

    public List<String> getExclude() {
        return exclude;
    }

    public void setExclude(List<String> exclude) {
        this.exclude = exclude;
        // Exclude takes precedence.
        this.include = null;
    }

    private void setExclude(TechSet techSet) {
        setExclude(TechnologyUtils.techSetToExcludeList(techSet));
    }

    public List<String> getInclude() {
        return include;
    }
}
