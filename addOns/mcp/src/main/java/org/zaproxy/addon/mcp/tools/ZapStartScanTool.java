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

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.zap.model.Context;

/** Abstract base for MCP tools that start a scan via an automation plan. */
public abstract class ZapStartScanTool implements McpTool {

    private static final Logger LOGGER = LogManager.getLogger(ZapStartScanTool.class);

    @Override
    public InputSchema getInputSchema() {
        Map<String, InputSchema.PropertyDef> properties = new LinkedHashMap<>();
        properties.put(
                "target",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString(getMessageKeyPrefix() + ".param.target")));
        addSupplementaryProperties(properties);
        return new InputSchema(properties, List.of("target"));
    }

    @Override
    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
        String target = arguments.getString("target");
        if (target == null || target.isBlank()) {
            throw new McpToolException(
                    Constant.messages.getString(getMessageKeyPrefix() + ".error.missingtarget"));
        }

        target = target.trim();

        String scanId;

        try {
            ExtensionAutomation extAutomation =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionAutomation.class);

            AutomationJob job = extAutomation.getAutomationJob(getJobName());
            if (job == null) {
                throw new McpToolException(
                        Constant.messages.getString(getJobNotAvailableErrorKey()));
            }
            job = job.newJob();

            AutomationPlan plan = new AutomationPlan();
            Session session = Model.getSingleton().getSession();
            Context context;

            if (isUrl(target)) {
                try {
                    new URI(target);
                } catch (Exception e) {
                    throw new McpToolException(
                            Constant.messages.getString(
                                    getMessageKeyPrefix() + ".error.invalidurl", target),
                            e);
                }
                String contextName = urlToContextName(target);
                Context existing = session.getContext(contextName);
                if (existing != null) {
                    session.deleteContext(existing);
                }
                context = session.getNewContext(contextName);
                context.addIncludeInContextRegex(target + ".*");
                session.saveContext(context);
                plan.getEnv().addContext(context);
            } else {
                context = session.getContext(target);
                if (context == null) {
                    throw new McpToolException(
                            Constant.messages.getString(
                                    getMessageKeyPrefix() + ".error.contextnotfound", target));
                }
                plan.getEnv().addContext(context);
            }
            configureJob(job, arguments);
            plan.addJob(job);

            extAutomation.registerPlan(plan);
            extAutomation.runPlanAsync(plan);

            try {
                scanId = extAutomation.getScanIdFuture(job).get(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.debug("Interrupted while starting scan", e);
                throw new McpToolException(
                        Constant.messages.getString(getMessageKeyPrefix() + ".error.failed"));
            }
        } catch (McpToolException e) {
            LOGGER.warn("Failed to start scan", e);
            throw e;
        } catch (Exception e) {
            LOGGER.error("Failed to start scan", e);
            throw new McpToolException(
                    Constant.messages.getString(getMessageKeyPrefix() + ".error.failed"));
        }

        return McpToolResult.success(
                Constant.messages.getString(getMessageKeyPrefix() + ".success", scanId));
    }

    private static boolean isUrl(String target) {
        String t = target.toLowerCase().trim();
        return t.startsWith("http://") || t.startsWith("https://");
    }

    private static String urlToContextName(String url) {
        String result = url.trim();
        String resultLc = result.toLowerCase(Locale.ROOT);
        if (resultLc.startsWith("https://")) {
            result = result.substring(8);
        } else if (resultLc.startsWith("http://")) {
            result = result.substring(7);
        }
        return result.isEmpty() ? url : result;
    }

    /**
     * Returns the message key prefix for this tool (e.g. "mcp.tool.startspider").
     *
     * @return the message key prefix
     */
    protected abstract String getMessageKeyPrefix();

    /**
     * Returns the automation job name (e.g. "spider", "spiderAjax", "activeScan").
     *
     * @return the job name
     */
    protected abstract String getJobName();

    /**
     * Returns the full message key for when the job is not available.
     *
     * @return the error message key
     */
    protected abstract String getJobNotAvailableErrorKey();

    /**
     * Adds supplementary schema properties (e.g. policy for active scan). Default does nothing.
     *
     * @param properties the schema properties map to add to
     */
    protected void addSupplementaryProperties(Map<String, InputSchema.PropertyDef> properties) {}

    /**
     * Configures the job before adding to the plan (e.g. set policy for active scan). Default does
     * nothing.
     *
     * @param job the automation job
     * @param arguments the tool arguments
     */
    protected void configureJob(AutomationJob job, ToolArguments arguments) {}
}
