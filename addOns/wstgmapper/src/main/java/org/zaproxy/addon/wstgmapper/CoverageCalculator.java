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

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.zaproxy.addon.wstgmapper.model.WstgCategory;
import org.zaproxy.addon.wstgmapper.model.WstgTest;
import org.zaproxy.addon.wstgmapper.model.WstgTestStatus;

/**
 * Computes the coverage numbers shown by the dashboard and the exporters.
 *
 * <p>This class combines the static WSTG catalogue with the mutable checklist state to answer
 * questions such as "how many tests are covered" and "which categories are complete".
 */
public class CoverageCalculator {

    public record CategoryStats(
            String categoryId,
            String categoryName,
            int totalTests,
            int completedTests,
            int incompleteTests,
            int notApplicableTests,
            double completionPercent) {

        public boolean isCompleted() {
            return totalTests > 0 && completionPercent >= 100.0;
        }

        public boolean isInProgress() {
            return completedTests > 0 && !isCompleted();
        }
    }

    private final WstgMapperData data;
    private final WstgMapperChecklistManager checklistManager;
    private final Set<String> automatedTestIds;

    public CoverageCalculator(
            WstgMapperData data,
            WstgMapperChecklistManager checklistManager,
            WstgMapperMappingManager mappingManager) {
        this.data = data;
        this.checklistManager = checklistManager;
        this.automatedTestIds = new LinkedHashSet<>(mappingManager.getAllMappedWstgIds());
        this.automatedTestIds.retainAll(data.getTestById().keySet());
    }

    public int getTotalTests() {
        return data.getTestById().size();
    }

    public int getAutomatedCount() {
        return automatedTestIds.size();
    }

    public boolean isAutomated(String testId) {
        return automatedTestIds.contains(testId);
    }

    public int getTriggeredCount() {
        int count = 0;
        for (String testId : data.getTestById().keySet()) {
            if (checklistManager.isTriggered(testId)) {
                count++;
            }
        }
        return count;
    }

    public int getManualOnlyCount() {
        return Math.max(0, getTotalTests() - getAutomatedCount());
    }

    public int getPassedCount() {
        return countByStatus(WstgTestStatus.PASSED);
    }

    public int getFailedCount() {
        return countByStatus(WstgTestStatus.FAILED);
    }

    public int getNotApplicableCount() {
        return countByStatus(WstgTestStatus.NOT_APPLICABLE);
    }

    public double getTestCoveragePercentage() {
        int total = getTotalTests();
        int notApplicable = getNotApplicableCount();
        int denominator = total - notApplicable;
        if (total == 0) {
            return 0.0;
        }
        if (denominator <= 0) {
            return 100.0;
        }

        int covered = 0;
        for (String testId : data.getTestById().keySet()) {
            if (isCovered(testId)) {
                covered++;
            }
        }
        return roundOneDecimal(100.0 * covered / denominator);
    }

    public int getTotalCategories() {
        return data.getCategories().size();
    }

    public int getCompletedCategoryCount() {
        int count = 0;
        for (CategoryStats stats : getAllCategoryStats()) {
            if (stats.isCompleted()) {
                count++;
            }
        }
        return count;
    }

    public double getCategoryCoveragePercentage() {
        int totalCategories = getTotalCategories();
        if (totalCategories == 0) {
            return 0.0;
        }
        return roundOneDecimal(100.0 * getCompletedCategoryCount() / totalCategories);
    }

    public CategoryStats getCategoryStats(String categoryId) {
        for (WstgCategory category : data.getCategories()) {
            if (category.getId().equals(categoryId)) {
                return calculateCategoryStats(category);
            }
        }
        return new CategoryStats(categoryId, categoryId, 0, 0, 0, 0, 0.0);
    }

    public List<CategoryStats> getAllCategoryStats() {
        List<CategoryStats> result = new ArrayList<>(data.getCategories().size());
        for (WstgCategory category : data.getCategories()) {
            result.add(calculateCategoryStats(category));
        }
        return List.copyOf(result);
    }

    private CategoryStats calculateCategoryStats(WstgCategory category) {
        int total = 0;
        int completed = 0;
        int notApplicable = 0;

        if (category.getTests() != null) {
            for (WstgTest test : category.getTests()) {
                total++;
                WstgTestStatus status = checklistManager.getTestStatus(test.getId());
                if (status == WstgTestStatus.NOT_APPLICABLE) {
                    notApplicable++;
                    continue;
                }
                if (isCovered(test.getId())) {
                    completed++;
                }
            }
        }

        int denominator = total - notApplicable;
        int incomplete = Math.max(0, total - notApplicable - completed);
        double percentage =
                denominator <= 0
                        ? (total == 0 ? 0.0 : 100.0)
                        : roundOneDecimal(100.0 * completed / denominator);
        return new CategoryStats(
                category.getId(),
                category.getName(),
                total,
                completed,
                incomplete,
                notApplicable,
                percentage);
    }

    private int countByStatus(WstgTestStatus status) {
        int count = 0;
        for (String testId : data.getTestById().keySet()) {
            if (checklistManager.getTestStatus(testId) == status) {
                count++;
            }
        }
        return count;
    }

    private boolean isCovered(String testId) {
        WstgTestStatus status = checklistManager.getTestStatus(testId);
        if (status == WstgTestStatus.NOT_APPLICABLE
                || status == WstgTestStatus.FAILED
                || status == WstgTestStatus.MANUAL_ONLY) {
            return false;
        }
        return status == WstgTestStatus.PASSED
                || (status == WstgTestStatus.NOT_TESTED && checklistManager.isTriggered(testId));
    }

    private static double roundOneDecimal(double value) {
        return Math.round(value * 10.0) / 10.0;
    }
}
