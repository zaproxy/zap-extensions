/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.mcp.tools;

import java.util.Map;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;

/** MCP tool that starts the active scan via an automation plan. */
public class ZapStartActiveScanTool extends ZapStartScanTool {

    @Override
    public String getName() {
        return "zap_start_active_scan";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.startactivescan.desc");
    }

    @Override
    protected String getMessageKeyPrefix() {
        return "mcp.tool.startactivescan";
    }

    @Override
    protected String getJobName() {
        return "activeScan";
    }

    @Override
    protected String getJobNotAvailableErrorKey() {
        return "mcp.tool.startactivescan.error.noactivescan";
    }

    @Override
    protected void addSupplementaryProperties(Map<String, InputSchema.PropertyDef> properties) {
        properties.put(
                "policy",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.startactivescan.param.policy")));
    }

    @Override
    protected void configureJob(AutomationJob job, ToolArguments arguments) {
        String policy = arguments.getString("policy");
        if (policy == null || policy.isBlank()) {
            return;
        }
        if (job instanceof ActiveScanJob ascJob) {
            ascJob.getParameters().setPolicy(policy.trim());
        }
    }
}
