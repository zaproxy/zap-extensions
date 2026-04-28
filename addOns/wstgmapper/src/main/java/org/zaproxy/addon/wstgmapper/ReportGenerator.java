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
package org.zaproxy.addon.wstgmapper;

import java.time.Clock;
import java.time.LocalDate;
import java.util.function.Supplier;
import org.zaproxy.addon.wstgmapper.model.WstgCategory;
import org.zaproxy.addon.wstgmapper.model.WstgTest;

/**
 * Generates the text reports exported by the add-on.
 *
 * <p>It translates the current checklist state and summary metrics into stable Markdown and CSV
 * output without depending on any Swing UI classes.
 */
public class ReportGenerator {

    private final Clock clock;
    private final Supplier<String> targetSupplier;
    private final String version;

    public ReportGenerator() {
        this(Clock.systemDefaultZone(), () -> "Current Session", "0.1.0");
    }

    ReportGenerator(Clock clock, Supplier<String> targetSupplier, String version) {
        this.clock = clock;
        this.targetSupplier = targetSupplier;
        this.version = version;
    }

    public String generateMarkdown(
            WstgMapperData data,
            WstgMapperChecklistManager checklistManager,
            CoverageCalculator coverageCalculator) {
        StringBuilder sb = new StringBuilder();
        sb.append("# WSTG Compliance Report\n\n");
        sb.append("**Target:** ").append(targetSupplier.get()).append('\n');
        sb.append("**Date:** ").append(LocalDate.now(clock)).append('\n');
        sb.append("**Tool:** ZAP + wstgmapper v").append(version).append("\n\n");

        sb.append("## Summary\n");
        sb.append("- Total tests: ").append(coverageCalculator.getTotalTests()).append('\n');
        sb.append("- Automated: ")
                .append(coverageCalculator.getAutomatedCount())
                .append(" (")
                .append(
                        percent(
                                coverageCalculator.getAutomatedCount(),
                                coverageCalculator.getTotalTests()))
                .append("%)\n");
        sb.append("- Triggered by alerts: ")
                .append(coverageCalculator.getTriggeredCount())
                .append('\n');
        sb.append("- Manually passed: ").append(coverageCalculator.getPassedCount()).append('\n');
        sb.append("- Manually failed: ").append(coverageCalculator.getFailedCount()).append('\n');
        sb.append("- Manual only (not automatable): ")
                .append(coverageCalculator.getManualOnlyCount())
                .append('\n');
        sb.append("- Not applicable: ")
                .append(coverageCalculator.getNotApplicableCount())
                .append('\n');
        sb.append("- **Effective coverage: ")
                .append(coverageCalculator.getTestCoveragePercentage())
                .append("%**\n\n");

        sb.append("## By Category\n");
        sb.append("| Category | ID | Total | Auto | Triggered | Manual | NA | Coverage |\n");
        sb.append("|---|---|---|---|---|---|---|---|\n");
        for (WstgCategory category : data.getCategories()) {
            CoverageCalculator.CategoryStats stats =
                    coverageCalculator.getCategoryStats(category.getId());
            int automated = 0;
            int triggered = 0;
            int manual = 0;
            if (category.getTests() != null) {
                for (WstgTest test : category.getTests()) {
                    if (coverageCalculator.isAutomated(test.getId())) {
                        automated++;
                    } else {
                        manual++;
                    }
                    if (checklistManager.isTriggered(test.getId())) {
                        triggered++;
                    }
                }
            }
            sb.append("| ")
                    .append(category.getName())
                    .append(" | ")
                    .append(category.getId())
                    .append(" | ")
                    .append(stats.totalTests())
                    .append(" | ")
                    .append(automated)
                    .append(" | ")
                    .append(triggered)
                    .append(" | ")
                    .append(manual)
                    .append(" | ")
                    .append(stats.notApplicableTests())
                    .append(" | ")
                    .append(stats.completionPercent())
                    .append("% |\n");
        }
        sb.append('\n');

        sb.append("## Tests\n");
        sb.append("| Category | Test ID | Name | Status | Triggered | Automated | Notes |\n");
        sb.append("|---|---|---|---|---|---|---|\n");
        for (WstgCategory category : data.getCategories()) {
            if (category.getTests() == null) {
                continue;
            }
            for (WstgTest test : category.getTests()) {
                sb.append("| ")
                        .append(category.getName())
                        .append(" | ")
                        .append(test.getId())
                        .append(" | ")
                        .append(escapeMarkdown(test.getName()))
                        .append(" | ")
                        .append(checklistManager.getTestStatus(test.getId()).name())
                        .append(" | ")
                        .append(checklistManager.isTriggered(test.getId()) ? "Yes" : "No")
                        .append(" | ")
                        .append(coverageCalculator.isAutomated(test.getId()) ? "Yes" : "No")
                        .append(" | ")
                        .append(escapeMarkdown(checklistManager.getTestNotes(test.getId())))
                        .append(" |\n");
            }
        }
        return sb.toString();
    }

    public String generateCsv(
            WstgMapperData data,
            WstgMapperChecklistManager checklistManager,
            CoverageCalculator coverageCalculator) {
        StringBuilder sb = new StringBuilder();
        sb.append("Category,Test ID,Test Name,Status,Triggered,Automated,Notes\n");
        for (WstgCategory category : data.getCategories()) {
            if (category.getTests() == null) {
                continue;
            }
            for (WstgTest test : category.getTests()) {
                sb.append(csv(category.getName()))
                        .append(',')
                        .append(csv(test.getId()))
                        .append(',')
                        .append(csv(test.getName()))
                        .append(',')
                        .append(csv(checklistManager.getTestStatus(test.getId()).name()))
                        .append(',')
                        .append(csv(checklistManager.isTriggered(test.getId()) ? "Yes" : "No"))
                        .append(',')
                        .append(csv(coverageCalculator.isAutomated(test.getId()) ? "Yes" : "No"))
                        .append(',')
                        .append(csv(checklistManager.getTestNotes(test.getId())))
                        .append('\n');
            }
        }
        return sb.toString();
    }

    private static double percent(int count, int total) {
        if (total <= 0) {
            return 0.0;
        }
        return Math.round(1000.0 * count / total) / 10.0;
    }

    private static String csv(String value) {
        String normalized = value != null ? value : "";
        if (normalized.contains(",")
                || normalized.contains("\"")
                || normalized.contains("\n")
                || normalized.contains("\r")) {
            return '"' + normalized.replace("\"", "\"\"") + '"';
        }
        return normalized;
    }

    private static String escapeMarkdown(String value) {
        return (value != null ? value : "").replace("|", "\\|").replace("\n", "<br>");
    }
}
