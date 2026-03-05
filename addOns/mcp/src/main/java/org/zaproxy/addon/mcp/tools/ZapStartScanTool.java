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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.LongRunningJob;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.zap.model.Context;

/** Abstract base for MCP tools that start a scan via an automation plan. */
public abstract class ZapStartScanTool implements McpTool {

    @Override
    public ObjectNode getInputSchema() {
        ObjectNode schema = OBJECT_MAPPER.createObjectNode();
        schema.put("type", "object");
        ObjectNode properties = schema.putObject("properties");
        properties
                .putObject("target")
                .put("type", "string")
                .put(
                        "description",
                        Constant.messages.getString(getMessageKeyPrefix() + ".param.target"));
        addSupplementarySchema(properties);
        schema.putArray("required").add("target");
        return schema;
    }

    @Override
    public McpToolResult execute(JsonNode arguments) throws McpToolException {
        JsonNode targetNode = arguments != null ? arguments.get("target") : null;
        if (targetNode == null || targetNode.isNull() || !targetNode.isTextual()) {
            throw new McpToolException(
                    Constant.messages.getString(getMessageKeyPrefix() + ".error.missingtarget"));
        }

        String target = targetNode.asText().trim();
        if (target.isEmpty()) {
            throw new McpToolException(
                    Constant.messages.getString(getMessageKeyPrefix() + ".error.emptytarget"));
        }

        String targetFinal = target;

        String scanId;

        try {
            ExtensionAutomation extAutomation =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionAutomation.class);

            AutomationJob job = extAutomation.getAutomationJob(getJobName());
            if (job == null) {
                throw new RuntimeException(
                        new McpToolException(
                                Constant.messages.getString(getJobNotAvailableErrorKey())));
            }
            job = job.newJob();

            AutomationPlan plan = new AutomationPlan();
            Session session = Model.getSingleton().getSession();
            Context context;

            if (isUrl(targetFinal)) {
                try {
                    new URI(targetFinal);
                } catch (Exception e) {
                    throw new RuntimeException(
                            new McpToolException(
                                    Constant.messages.getString(
                                            getMessageKeyPrefix() + ".error.invalidurl",
                                            targetFinal),
                                    e));
                }
                String contextName = urlToContextName(targetFinal);
                Context existing = session.getContext(contextName);
                if (existing != null) {
                    session.deleteContext(existing);
                }
                context = session.getNewContext(contextName);
                context.addIncludeInContextRegex(targetFinal + ".*");
                session.saveContext(context);
                plan.getEnv().addContext(context);
            } else {
                context = session.getContext(targetFinal);
                if (context == null) {
                    throw new RuntimeException(
                            new McpToolException(
                                    Constant.messages.getString(
                                            getMessageKeyPrefix() + ".error.contextnotfound",
                                            targetFinal)));
                }
                plan.getEnv().addContext(context);
            }
            configureJob(job, arguments);
            plan.addJob(job);

            extAutomation.registerPlan(plan);
            extAutomation.runPlanAsync(plan);

            scanId = waitForScanId((LongRunningJob) job, job);
        } catch (Exception e) {
            Throwable cause = e.getCause();
            if (cause instanceof McpToolException mte) {
                throw mte;
            }
            throw new McpToolException(
                    Constant.messages.getString(
                            getMessageKeyPrefix() + ".error.failed", e.getMessage()),
                    e);
        }

        return McpToolResult.success(
                Constant.messages.getString(getMessageKeyPrefix() + ".success", scanId));
    }

    private String waitForScanId(LongRunningJob longRunningJob, AutomationJob job) {
        int maxAttempts = 50;
        int sleepMs = 200;
        for (int i = 0; i < maxAttempts; i++) {
            try {
                Thread.sleep(sleepMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(
                        new McpToolException(
                                Constant.messages.getString(
                                        getMessageKeyPrefix() + ".error.failed", e.getMessage()),
                                e));
            }
            String id = longRunningJob.getScanId();
            if (id != null) {
                return id;
            }
            if (job.getStatus() == AutomationJob.Status.COMPLETED) {
                throw new RuntimeException(
                        new McpToolException(
                                Constant.messages.getString(
                                        getMessageKeyPrefix() + ".error.failed",
                                        getJobFinishedWithoutStartingMessage())));
            }
        }
        throw new RuntimeException(
                new McpToolException(
                        Constant.messages.getString(
                                getMessageKeyPrefix() + ".error.failed", "timeout")));
    }

    private static boolean isUrl(String target) {
        String t = target.toLowerCase().trim();
        return t.startsWith("http://") || t.startsWith("https://");
    }

    private static String urlToContextName(String url) {
        String result = url.trim();
        if (result.toLowerCase().startsWith("https://")) {
            result = result.substring(8);
        } else if (result.toLowerCase().startsWith("http://")) {
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
     * Returns the message for when the job finished without starting.
     *
     * @return the message
     */
    protected abstract String getJobFinishedWithoutStartingMessage();

    /**
     * Adds supplementary schema properties (e.g. policy for active scan). Default does nothing.
     *
     * @param properties the schema properties object to add to
     */
    protected void addSupplementarySchema(ObjectNode properties) {}

    /**
     * Configures the job before adding to the plan (e.g. set policy for active scan). Default does
     * nothing.
     *
     * @param job the automation job
     * @param arguments the tool arguments
     */
    protected void configureJob(AutomationJob job, JsonNode arguments) {}
}
