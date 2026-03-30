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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestClientWindowClose;
import org.zaproxy.zest.core.v1.ZestClientWindowHandle;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

/**
 * Internal utility that builds one runnable Zest script from a chain (shared browser session).
 *
 * <p>Statement-to-source mapping for that script lives in {@link ChainProvenance}, produced during
 * {@link #mergeScripts}.
 */
public final class ZestScriptMerger {

    private ZestScriptMerger() {}

    /**
     * Builds one runnable Zest script from an ordered chain (shared browser session).
     *
     * <p>The process:
     *
     * <ul>
     *   <li>Uses type and engine from the first script; title is set to {@code chainRunName}
     *   <li>Disables redundant {@code ZestClientLaunch} statements in scripts after the first
     *   <li>Concatenates all statements in chain order
     *   <li>Appends {@code ZestClientWindowClose} at the end when the first script launches a
     *       browser: one close per window handle (from {@code ZestClientLaunch} and {@code
     *       ZestClientWindowHandle}), so windows are closed when the chain finishes
     * </ul>
     *
     * @param scripts list of Zest script wrappers in chain order (must not be empty)
     * @param chainRunName name for the generated script wrapper and Zest title (e.g. automation run
     *     label)
     * @param scriptSerializer converts the chain script to JSON/text contents
     * @return a new {@link ZestScriptWrapper} for the chain run
     * @throws IllegalArgumentException if scripts list is null or empty, or if the first script
     *     contains no ZestClientLaunch statement
     */
    public static ZestScriptWrapper mergeScripts(
            List<ZestScriptWrapper> scripts,
            String chainRunName,
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

        ZestScript chainedScript = new ZestScript();
        chainedScript.setTitle(chainRunName);
        chainedScript.setType(firstZestScript.getType());
        chainedScript.setDescription("");

        List<ChainProvenance.ChainSegment> segments = new ArrayList<>(scripts.size());
        List<ChainProvenance.StatementOrigin> orderedOrigins = new ArrayList<>();

        Set<String> windowHandles = new LinkedHashSet<>();
        for (int scriptIndex = 0; scriptIndex < scripts.size(); scriptIndex++) {
            ZestScriptWrapper scriptWrapper = scripts.get(scriptIndex);
            ZestScript script = scriptWrapper.getZestScript();
            List<ZestStatement> statements = script.getStatements();

            segments.add(
                    new ChainProvenance.ChainSegment(
                            scriptIndex, chainSegmentDisplayName(scriptWrapper)));

            // Add statements (disable ZestClientLaunch for scripts after the first)
            for (ZestStatement statement : statements) {
                // Deep copy the statement to avoid modifying original
                ZestStatement copiedStatement = statement.deepCopy();

                if (scriptIndex > 0 && copiedStatement instanceof ZestClientLaunch) {
                    copiedStatement.setEnabled(false);
                }

                chainedScript.add(copiedStatement);
                orderedOrigins.add(
                        new ChainProvenance.StatementOrigin(
                                scriptIndex,
                                statement.getIndex(),
                                copiedStatement.getElementType()));
                addHandleIfClientWindow(copiedStatement, windowHandles);
            }
        }

        // Close all browser windows at end when the first script launched one
        if (countEnabledClientLaunches(firstZestScript) > 0 && !windowHandles.isEmpty()) {
            int cleanupSegmentIndex = segments.size();
            segments.add(new ChainProvenance.ChainSegment(cleanupSegmentIndex, "-"));
            for (String handle : windowHandles) {
                ZestClientWindowClose closeStatement = new ZestClientWindowClose();
                closeStatement.setWindowHandle(handle);
                chainedScript.add(closeStatement);
                orderedOrigins.add(
                        new ChainProvenance.StatementOrigin(
                                cleanupSegmentIndex, -1, closeStatement.getElementType()));
            }
        }

        // Create wrapper via serialization (no setZestScript method exists)
        String chainedJson = scriptSerializer.apply(chainedScript);
        if (chainedJson == null) {
            throw new IllegalStateException(
                    "Script serializer returned null chained script contents");
        }

        ScriptWrapper sw = new ScriptWrapper();
        sw.setName(chainRunName);
        sw.setContents(chainedJson);
        sw.setType(firstScript.getType());
        sw.setEngine(firstScript.getEngine());

        ZestScriptWrapper zestWrapper = new ZestScriptWrapper(sw);
        ZestScript parsed = zestWrapper.getZestScript();
        ChainProvenance provenance =
                ChainProvenance.finalizeMapping(segments, orderedOrigins, parsed);
        zestWrapper.setChainProvenance(provenance);
        prepareChainedWrapperForRun(zestWrapper);
        return zestWrapper;
    }

    /**
     * Clears per-run failure diagnostics on a newly built chain wrapper (see {@link
     * org.zaproxy.zap.extension.zest.ZestScriptWrapper#setZestFailureContext}).
     */
    private static void prepareChainedWrapperForRun(ZestScriptWrapper zestWrapper) {
        zestWrapper.setZestFailureContext("");
    }

    /**
     * Non-empty label for {@link ChainProvenance.ChainSegment#scriptName()}; {@code "-"} when the
     * wrapper has no usable name so {@link ChainProvenance#describe(int)} need not null-check.
     */
    private static String chainSegmentDisplayName(ZestScriptWrapper scriptWrapper) {
        String name = scriptWrapper.getName();
        return (name == null || name.isBlank()) ? "-" : name;
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

    /**
     * Maps chain-script Zest statement indices back to the original chain member and statement for
     * logging and diagnostics. Built only by {@link #mergeScripts}.
     */
    public static final class ChainProvenance {

        /**
         * One entry per script in chain order (0-based segment index), plus an optional trailing
         * segment for synthetic window closes when those are appended. {@code scriptName} is always
         * non-blank ({@code "-"} when the source wrapper has no name).
         */
        public record ChainSegment(int segmentIndex, String scriptName) {}

        /**
         * Origin of one statement in the chain script. {@code originalStatementIndex} is the source
         * statement's Zest index ({@link ZestStatement#getIndex()}), or -1 for synthetic chain rows
         * (e.g. appended window closes).
         */
        public record StatementOrigin(
                int segmentIndex, int originalStatementIndex, String elementType) {}

        private final List<ChainSegment> segments;
        private final Map<Integer, StatementOrigin> byZestStatementIndex;

        private ChainProvenance(
                List<ChainSegment> segments, Map<Integer, StatementOrigin> byZestStatementIndex) {
            this.segments = List.copyOf(segments);
            this.byZestStatementIndex = Map.copyOf(byZestStatementIndex);
        }

        /**
         * Human-readable context for a failing statement (i18n). Omits the synthetic chain run name
         * so diagnostics refer only to real source scripts and indices.
         *
         * @param zestStatementIndex Zest statement index in the <strong>merged chain</strong>
         *     script (from {@link ZestStatement#getIndex()} while that chain runs), used only to
         *     look up provenance; the message shows {@link
         *     StatementOrigin#originalStatementIndex()} from the source script (or "-" when that
         *     index is not applicable, e.g. synthetic chain rows).
         */
        public String describe(int zestStatementIndex) {
            StatementOrigin o = byZestStatementIndex.get(zestStatementIndex);
            if (o == null) {
                return Constant.messages.getString(
                        "zest.chainprovenance.unknown", Integer.toString(zestStatementIndex));
            }
            ChainSegment seg = segments.get(o.segmentIndex());
            int sourceIdx = o.originalStatementIndex();
            String indexForMessage = sourceIdx >= 0 ? Integer.toString(sourceIdx) : "-";
            return Constant.messages.getString(
                    "zest.chainprovenance.detail",
                    indexForMessage,
                    seg.scriptName(),
                    o.elementType());
        }

        /**
         * Builds the index map after the chain script has been parsed (JSON round-trip). Statement
         * order must match {@code orderedOrigins}.
         */
        static ChainProvenance finalizeMapping(
                List<ChainSegment> segments,
                List<StatementOrigin> orderedOrigins,
                ZestScript parsedChainScript) {
            List<ZestStatement> stmts = parsedChainScript.getStatements();
            Map<Integer, StatementOrigin> map = new HashMap<>();
            int n = Math.min(stmts.size(), orderedOrigins.size());
            for (int i = 0; i < n; i++) {
                map.put(stmts.get(i).getIndex(), orderedOrigins.get(i));
            }
            return new ChainProvenance(segments, map);
        }
    }
}
