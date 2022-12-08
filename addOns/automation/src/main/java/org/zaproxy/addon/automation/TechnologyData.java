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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.TechSet;

public class TechnologyData extends AutomationData {

    private List<String> exclude;

    public TechnologyData() {
        exclude = new ArrayList<>();
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
        context.setTechSet(TechnologyUtils.getTechSet(exclude));
    }

    public TechnologyData(Object data, AutomationProgress progress) {
        this();
        if (!(data instanceof LinkedHashMap)) {
            progress.error(Constant.messages.getString("automation.error.context.badtech", data));
        } else {
            LinkedHashMap<?, ?> dataMap = (LinkedHashMap<?, ?>) data;

            for (Entry<?, ?> cdata : dataMap.entrySet()) {
                if ("exclude".equals(cdata.getKey().toString())) {
                    Object value = cdata.getValue();
                    if (value == null) {
                        continue;
                    }
                    if (!(value instanceof ArrayList)) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.context.badtechexclude", value));

                    } else {
                        ArrayList<?> urlList = (ArrayList<?>) value;
                        for (Object urlObj : urlList) {
                            String techName = urlObj.toString();
                            exclude.add(techName);
                            // Check it exists
                            TechnologyUtils.getTech(techName, progress);
                        }
                    }
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

    public List<String> getExclude() {
        return exclude;
    }

    public void setExclude(List<String> exclude) {
        this.exclude = exclude;
    }

    public void setExclude(TechSet techSet) {
        this.exclude = TechnologyUtils.techSetToExcludeList(techSet);
    }
}
