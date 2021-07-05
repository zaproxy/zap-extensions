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
package org.zaproxy.addon.automation.jobs;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.extension.params.ExtensionParams;
import org.zaproxy.zap.extension.params.HtmlParameterStats;
import org.zaproxy.zap.extension.params.SiteParameters;

public class ParamsJobResultData extends JobResultData {

    public static final String DATA_KEY = "paramsData";
    public static final String I18N_TYPE_PREFIX = "automation.params.type.";

    private ExtensionParams extensionParams;

    private static Comparator<HtmlParameterStats> BY_TYPE_AND_NAME =
            (HtmlParameterStats o1, HtmlParameterStats o2) ->
                    o1.getType().equals(o2.getType())
                            ? o1.getName().compareTo(o2.getName())
                            : o1.getType().compareTo(o2.getType());

    public ParamsJobResultData(String jobName) {
        super(jobName);

        extensionParams =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionParams.class);
    }

    public SiteParameters getSiteParameters(String site) {
        if (extensionParams != null) {
            int offset = site.indexOf("://");
            if (offset > 0) {
                // The params extension doesn't use the initial http(s)://
                site = site.substring(offset + 3);
            }
            return extensionParams.getSiteParameters(site);
        }
        return null;
    }

    public List<HtmlParameterStats> getSortedSiteParams(String site) {
        SiteParameters siteParams = this.getSiteParameters(site);
        if (siteParams != null) {
            List<HtmlParameterStats> params = siteParams.getParams();
            params.sort(BY_TYPE_AND_NAME);
            return params;
        }
        return null;
    }

    public Collection<SiteParameters> getAllSiteParameters() {
        if (extensionParams != null) {
            return extensionParams.getAllSiteParameters();
        }
        return null;
    }

    public static String getTypeString(String type) {
        if (Constant.messages.containsKey(I18N_TYPE_PREFIX + type)) {
            return Constant.messages.getString(I18N_TYPE_PREFIX + type);
        }
        return Constant.messages.getString(I18N_TYPE_PREFIX + "unknown");
    }

    @Override
    public String getKey() {
        return DATA_KEY;
    }
}
