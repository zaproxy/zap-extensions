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
package org.zaproxy.zap.extension.ascanrulesBeta;

import org.zaproxy.addon.commonlib.AbstractAppFilePlugin;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Active scan rule which checks whether or not trace.axd is exposed.
 * https://github.com/zaproxy/zaproxy/issues/3280
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class TraceAxdScanRule extends AbstractAppFilePlugin {

    private static final String MESSAGE_PREFIX = "ascanbeta.traceaxd.";
    private static final int PLUGIN_ID = 40029;

    public TraceAxdScanRule() {
        super("trace.axd", MESSAGE_PREFIX);
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.IIS)
                || technologies.includes(Tech.Windows)
                || technologies.includes(Tech.ASP)
                || technologies.includes(Tech.MsSQL);
    }
}
