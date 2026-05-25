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
package org.zaproxy.addon.commonlib.ui;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import javax.swing.JOptionPane;
import javax.swing.tree.TreeNode;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.ZapLabel;
import org.zaproxy.zap.view.HrefTypeInfo;
import org.zaproxy.zap.view.popup.PopupMenuItemSiteNodeContainer;

/**
 * Context menu item on the Sites tree that summarizes the selected node's subtree.
 *
 * <p>Surfaces a quick "what does this branch of the Sites tree actually contain" view without
 * having to walk it manually. The summary covers:
 *
 * <ul>
 *   <li>Total descendant node count.
 *   <li>Timestamp of the most recently added descendant, computed off {@link
 *       HistoryReference#getTimeSentMillis()}.
 *   <li>A breakdown of source types (via {@link HrefTypeInfo#getFromType(int)}), so the user can
 *       tell at a glance whether the branch came from passive proxying, the spider, AJAX spider,
 *       fuzzing, etc.
 * </ul>
 *
 * <p>The values are computed on demand rather than precomputed, since the Sites tree can be very
 * large and incrementally maintaining these counters per node would be wasted work for a feature
 * that is only triggered explicitly. Walking the subtree once on click is fast in practice — even a
 * 10k-node branch is well under a second on commodity hardware.
 */
@SuppressWarnings("serial")
public class SitesTreeInfoMenu extends PopupMenuItemSiteNodeContainer {

    private static final long serialVersionUID = 1L;

    static final DateTimeFormatter LAST_ADDED_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z").withZone(ZoneId.systemDefault());

    public SitesTreeInfoMenu() {
        super(Constant.messages.getString("commonlib.sitestree.info.menu"), false);
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    @Override
    protected void performAction(SiteNode siteNode) {
        JOptionPane.showMessageDialog(
                View.getSingleton().getMainFrame(),
                new ZapLabel(createSummary(siteNode)),
                Constant.messages.getString("commonlib.sitestree.info.title"),
                JOptionPane.INFORMATION_MESSAGE);
    }

    static String createSummary(SiteNode siteNode) {
        SubtreeSummary summary = summarize(siteNode);
        return Constant.messages.getString(
                "commonlib.sitestree.info.body",
                summary.totalNodes,
                formatLastAdded(summary.lastAddedMillis),
                formatSources(summary.sourceCounts));
    }

    /** Walk the subtree rooted at {@code root} (inclusive) and accumulate the summary fields. */
    private static SubtreeSummary summarize(SiteNode root) {
        SubtreeSummary summary = new SubtreeSummary();
        accumulate(root, summary);
        return summary;
    }

    private static void accumulate(SiteNode node, SubtreeSummary summary) {
        if (node == null) {
            return;
        }
        summary.totalNodes++;

        HistoryReference href = node.getHistoryReference();
        if (href != null) {
            long ts = href.getTimeSentMillis();
            if (ts > summary.lastAddedMillis) {
                summary.lastAddedMillis = ts;
            }
            summary.sourceCounts.merge(
                    HrefTypeInfo.getFromType(href.getHistoryType()).toString(), 1, Integer::sum);
        }

        Enumeration<TreeNode> children = node.children();
        while (children.hasMoreElements()) {
            TreeNode child = children.nextElement();
            if (child instanceof SiteNode sn) {
                accumulate(sn, summary);
            }
        }
    }

    private static String formatLastAdded(long millis) {
        if (millis <= 0) {
            return Constant.messages.getString("commonlib.sitestree.info.lastadded.unknown");
        }
        return LAST_ADDED_FORMAT.format(Instant.ofEpochMilli(millis));
    }

    /** Format the source-counts map as a sorted, human-readable list. */
    private static String formatSources(Map<String, Integer> sourceCounts) {
        if (sourceCounts.isEmpty()) {
            return Constant.messages.getString("commonlib.sitestree.info.sources.none");
        }
        // Sort by count desc, then label asc, so the dominant source is first and ties resolve
        // deterministically.
        Map<String, Integer> ordered = new LinkedHashMap<>();
        sourceCounts.entrySet().stream()
                .sorted(
                        Comparator.comparingInt(Map.Entry<String, Integer>::getValue)
                                .reversed()
                                .thenComparing(Map.Entry::getKey))
                .forEach(e -> ordered.put(e.getKey(), e.getValue()));

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Integer> entry : ordered.entrySet()) {
            if (!sb.isEmpty()) {
                sb.append('\n');
            }
            sb.append("  ").append(entry.getKey()).append(": ").append(entry.getValue());
        }
        return sb.toString();
    }

    /** Mutable accumulator used by {@link #summarize(SiteNode)}. */
    private static final class SubtreeSummary {
        int totalNodes;
        long lastAddedMillis;
        Map<String, Integer> sourceCounts = new TreeMap<>();
    }
}
