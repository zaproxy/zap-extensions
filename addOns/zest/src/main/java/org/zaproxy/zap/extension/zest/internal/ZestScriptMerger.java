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
package org.zaproxy.zap.extension.zest.internal;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestClientWindowClose;
import org.zaproxy.zest.core.v1.ZestClientWindowHandle;
import org.zaproxy.zest.core.v1.ZestComment;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

/**
 * Utility class for merging multiple Zest scripts into a single script.
 *
 * <p>This is used internally by Zest chain execution to combine multiple scripts into one usable
 * script that shares browser sessions and WebDriver instances.
 */
public final class ZestScriptMerger {

    private ZestScriptMerger() {}

    /**
     * Merges multiple Zest scripts into a single script.
     *
     * <p>The merge process:
     *
     * <ul>
     *   <li>Uses type and engine from the first script; title and description are set to {@code
     *       mergedScriptName} and a generated "Merged chain of N scripts" description
     *   <li>Inserts section comments to mark the start of each original script
     *   <li>Disables redundant ZestClientLaunch statements (scripts after the first)
     *   <li>Combines all statements into a single script
     *   <li>Appends ZestClientWindowClose statements at the end when the first script launches a
     *       browser: one close per window handle introduced (from ZestClientLaunch and
     *       ZestClientWindowHandle), so all browser windows are closed when the chain finishes
     * </ul>
     *
     * @param scripts List of ZestScriptWrapper objects to merge (must not be empty)
     * @param mergedScriptName Name for the merged script (used as title)
     * @param scriptSerializer Function that converts the merged script to JSON/text contents
     * @return A new ZestScriptWrapper containing the merged script
     * @throws IllegalArgumentException if scripts list is null or empty, or if the first script
     *     contains no ZestClientLaunch statement
     */
    public static ZestScriptWrapper mergeScripts(
            List<ZestScriptWrapper> scripts,
            String mergedScriptName,
            Function<ZestScript, String> scriptSerializer) {
        if (scripts == null || scripts.isEmpty()) {
            throw new IllegalArgumentException("Scripts list must not be null or empty");
        }
        if (scriptSerializer == null) {
            throw new IllegalArgumentException("Script serializer must not be null");
        }

        ZestScriptWrapper firstScript = scripts.get(0);
        ZestScript firstZestScript = firstScript.getZestScript();

        if (countEnabledClientLaunches(firstZestScript) == 0) {
            throw new IllegalArgumentException(
                    "First script in chain must contain at least one ZestClientLaunch statement: "
                            + firstScript.getName());
        }

        ZestScript mergedScript = new ZestScript();
        mergedScript.setTitle(mergedScriptName);
        mergedScript.setType(firstZestScript.getType());
        mergedScript.setDescription("Merged chain of " + scripts.size() + " scripts");

        Set<String> windowHandles = new LinkedHashSet<>();
        for (int scriptIndex = 0; scriptIndex < scripts.size(); scriptIndex++) {
            ZestScriptWrapper scriptWrapper = scripts.get(scriptIndex);
            ZestScript script = scriptWrapper.getZestScript();
            List<ZestStatement> statements = script.getStatements();

            int originalStatementCount = statements.size();
            int disabledLaunchCount = (scriptIndex == 0) ? 0 : countEnabledClientLaunches(script);

            ZestComment startComment =
                    createSectionComment(
                            scriptWrapper.getName(),
                            scriptWrapper.getFile() != null
                                    ? scriptWrapper.getFile().getName()
                                    : null,
                            originalStatementCount,
                            disabledLaunchCount);
            mergedScript.add(startComment);

            // Add statements (disable ZestClientLaunch for scripts after the first)
            for (ZestStatement statement : statements) {
                // Deep copy the statement to avoid modifying original
                ZestStatement copiedStatement = statement.deepCopy();

                if (scriptIndex > 0 && copiedStatement instanceof ZestClientLaunch) {
                    copiedStatement.setEnabled(false);
                }

                mergedScript.add(copiedStatement);
                addHandleIfClientWindow(copiedStatement, windowHandles);
            }
        }

        // Close all browser windows at end when the first script launched one
        if (countEnabledClientLaunches(firstZestScript) > 0 && !windowHandles.isEmpty()) {
            mergedScript.add(new ZestComment("=== END: close all windows (added by merger) ==="));
            for (String handle : windowHandles) {
                ZestClientWindowClose closeStatement = new ZestClientWindowClose();
                closeStatement.setWindowHandle(handle);
                mergedScript.add(closeStatement);
            }
        }

        // Create wrapper via serialization (no setZestScript method exists)
        String mergedJson = scriptSerializer.apply(mergedScript);
        if (mergedJson == null) {
            throw new IllegalStateException(
                    "Script serializer returned null merged script contents");
        }

        ScriptWrapper sw = new ScriptWrapper();
        sw.setName(mergedScriptName);
        sw.setContents(mergedJson);
        sw.setType(firstScript.getType());
        sw.setEngine(firstScript.getEngine());

        // Create ZestScriptWrapper (parses JSON automatically)
        return new ZestScriptWrapper(sw);
    }

    /**
     * Creates a section comment marking the start of a script in the merged chain.
     *
     * @param scriptName Name of the script
     * @param filename Filename of the script (can be null for inline scripts)
     * @param originalStatementCount Number of statements in the original script
     * @param disabledLaunchCount Number of ZestClientLaunch statements that were disabled
     * @return A ZestComment with the section information
     */
    private static ZestComment createSectionComment(
            String scriptName,
            String filename,
            int originalStatementCount,
            int disabledLaunchCount) {

        StringBuilder commentText = new StringBuilder();
        commentText.append("=== START: ").append(scriptName).append(" ===\n");

        if (filename != null) {
            commentText.append("Original script: ").append(filename).append("\n");
        }

        commentText.append("Original statement count: ").append(originalStatementCount);

        if (disabledLaunchCount > 0) {
            commentText
                    .append("\nNote: ")
                    .append(disabledLaunchCount)
                    .append(
                            " ZestClientLaunch statement(s) disabled (reusing browser from first script)");
        }

        return new ZestComment(commentText.toString());
    }

    /**
     * Adds the window handle from a ZestClientLaunch or ZestClientWindowHandle statement to the set
     * (insertion order preserved via LinkedHashSet).
     */
    private static void addHandleIfClientWindow(ZestStatement statement, Set<String> handles) {
        if (!statement.isEnabled()) {
            return;
        }

        if (statement instanceof ZestClientLaunch launch) {
            addHandleIfNotBlank(launch.getWindowHandle(), handles);
        } else if (statement instanceof ZestClientWindowHandle windowHandle) {
            addHandleIfNotBlank(windowHandle.getWindowHandle(), handles);
        }
    }

    private static void addHandleIfNotBlank(String handle, Set<String> handles) {
        if (handle != null && !handle.isEmpty()) {
            handles.add(handle);
        }
    }

    /**
     * Counts the number of ZestClientLaunch statements in a script.
     *
     * @param script The ZestScript to analyze
     * @return The count of ZestClientLaunch statements
     */
    private static int countEnabledClientLaunches(ZestScript script) {
        int count = 0;
        for (ZestStatement statement : script.getStatements()) {
            if (statement instanceof ZestClientLaunch && statement.isEnabled()) {
                count++;
            }
        }
        return count;
    }
}
