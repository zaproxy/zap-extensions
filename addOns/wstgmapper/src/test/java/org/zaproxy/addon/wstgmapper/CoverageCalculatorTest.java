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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.wstgmapper.model.WstgCategory;
import org.zaproxy.addon.wstgmapper.model.WstgTest;
import org.zaproxy.addon.wstgmapper.model.WstgTestStatus;

/**
 * Unit tests for {@link CoverageCalculator}.
 *
 * <p>These checks protect the summary math behind the dashboard and exports, especially around
 * triggered tests, manual overrides, and not-applicable coverage handling.
 */
class CoverageCalculatorTest {

    private CoverageCalculator calculator;

    @BeforeEach
    void setUp() {
        WstgMapperData data =
                new WstgMapperData(
                        List.of(
                                category(
                                        "INFO",
                                        "Information Gathering",
                                        "WSTG-INFO-01",
                                        "WSTG-INFO-02"),
                                category(
                                        "SESS",
                                        "Session Management",
                                        "WSTG-SESS-01",
                                        "WSTG-SESS-02")));
        WstgMapperChecklistManager manager = new WstgMapperChecklistManager(null);
        manager.triggerTests(Set.of("WSTG-INFO-01"));
        manager.setTestStatus("WSTG-INFO-02", WstgTestStatus.PASSED);
        manager.setTestStatus("WSTG-SESS-01", WstgTestStatus.NOT_APPLICABLE);
        manager.setTestStatus("WSTG-SESS-02", WstgTestStatus.FAILED);

        calculator =
                new CoverageCalculator(
                        data,
                        manager,
                        new WstgMapperMappingManager(
                                Map.of(10010, Set.of("WSTG-INFO-01", "WSTG-SESS-02")), Map.of()));
    }

    @Test
    void calculatesTopLevelCoverageCounts() {
        assertThat(calculator.getTotalTests(), is(4));
        assertThat(calculator.getAutomatedCount(), is(2));
        assertThat(calculator.getTriggeredCount(), is(1));
        assertThat(calculator.getManualOnlyCount(), is(2));
        assertThat(calculator.getPassedCount(), is(1));
        assertThat(calculator.getFailedCount(), is(1));
        assertThat(calculator.getNotApplicableCount(), is(1));
        assertThat(calculator.getTestCoveragePercentage(), is(66.7));
    }

    @Test
    void calculatesCategoryCoverageBreakdown() {
        CoverageCalculator.CategoryStats infoStats = calculator.getCategoryStats("INFO");
        CoverageCalculator.CategoryStats sessionStats = calculator.getCategoryStats("SESS");

        assertThat(infoStats.completedTests(), is(2));
        assertThat(infoStats.incompleteTests(), is(0));
        assertThat(infoStats.completionPercent(), is(100.0));
        assertThat(infoStats.isCompleted(), is(true));

        assertThat(sessionStats.completedTests(), is(0));
        assertThat(sessionStats.incompleteTests(), is(1));
        assertThat(sessionStats.notApplicableTests(), is(1));
        assertThat(sessionStats.completionPercent(), is(0.0));
    }

    @Test
    void calculatesOverallCategoryCompletion() {
        assertThat(calculator.getCompletedCategoryCount(), is(1));
        assertThat(calculator.getCategoryCoveragePercentage(), is(50.0));
    }

    @Test
    void calculatesZeroCoverageForUntouchedChecklist() {
        WstgMapperData data =
                new WstgMapperData(
                        List.of(category("INFO", "Information Gathering", "WSTG-INFO-01")));
        CoverageCalculator untouchedCalculator =
                new CoverageCalculator(
                        data,
                        new WstgMapperChecklistManager(null),
                        new WstgMapperMappingManager(Map.of(), Map.of()));

        CoverageCalculator.CategoryStats stats = untouchedCalculator.getCategoryStats("INFO");

        assertThat(untouchedCalculator.getTriggeredCount(), is(0));
        assertThat(untouchedCalculator.getPassedCount(), is(0));
        assertThat(untouchedCalculator.getFailedCount(), is(0));
        assertThat(untouchedCalculator.getNotApplicableCount(), is(0));
        assertThat(untouchedCalculator.getTestCoveragePercentage(), is(0.0));
        assertThat(untouchedCalculator.getCompletedCategoryCount(), is(0));
        assertThat(untouchedCalculator.getCategoryCoveragePercentage(), is(0.0));
        assertThat(stats.completedTests(), is(0));
        assertThat(stats.incompleteTests(), is(1));
        assertThat(stats.completionPercent(), is(0.0));
        assertThat(stats.isCompleted(), is(false));
    }

    @Test
    void doesNotTreatEmptyCategoriesAsCompleted() {
        WstgMapperData data =
                new WstgMapperData(List.of(new WstgCategory("EMPTY", "Empty", List.of())));
        CoverageCalculator emptyCalculator =
                new CoverageCalculator(
                        data,
                        new WstgMapperChecklistManager(null),
                        new WstgMapperMappingManager(Map.of(), Map.of()));

        CoverageCalculator.CategoryStats stats = emptyCalculator.getCategoryStats("EMPTY");

        assertThat(stats.totalTests(), is(0));
        assertThat(stats.completionPercent(), is(0.0));
        assertThat(stats.isCompleted(), is(false));
        assertThat(emptyCalculator.getCompletedCategoryCount(), is(0));
        assertThat(emptyCalculator.getCategoryCoveragePercentage(), is(0.0));
    }

    private static WstgCategory category(String id, String name, String... testIds) {
        List<WstgTest> tests = new java.util.ArrayList<>(testIds.length);
        for (String testId : testIds) {
            tests.add(test(testId, testId));
        }
        return new WstgCategory(id, name, List.copyOf(tests));
    }

    private static WstgTest test(String id, String name) {
        return new WstgTest(
                id, name, List.of("Objective"), "How to test", List.of("https://example.com"));
    }
}
