/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import java.util.Map;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.AbstractHostFilePlugin;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Active scan rule which checks whether or not elmah.axd is exposed.
 * https://github.com/zaproxy/zaproxy/issues/3279
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class ElmahScanRule extends AbstractHostFilePlugin {

    private static final String MESSAGE_PREFIX = "ascanrules.elmah.";
    private static final int PLUGIN_ID = 40028;

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE);

    public ElmahScanRule() {
        super("/elmah.axd", MESSAGE_PREFIX);
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.IIS)
                || technologies.includes(Tech.Windows)
                || technologies.includes(Tech.ASP)
                || technologies.includes(Tech.MsSQL);
    }

    @Override
    public boolean hasContent(HttpMessage msg) {
        return msg.getResponseBody().toString().contains("Error Log for");
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
        return 94; // Configuration
    }

    @Override
    public int getWascId() {
        return 14; // Server Misconfiguration
    }
}
