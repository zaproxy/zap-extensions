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
package org.zaproxy.addon.wstgmapper.ui;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.wstgmapper.CoverageCalculator;
import org.zaproxy.addon.wstgmapper.WstgMapperChecklistManager;
import org.zaproxy.addon.wstgmapper.WstgMapperData;
import org.zaproxy.addon.wstgmapper.model.WstgCategory;
import org.zaproxy.addon.wstgmapper.model.WstgTest;
import org.zaproxy.addon.wstgmapper.model.WstgTestStatus;

/**
 * Swing table model for the main checklist view.
 *
 * <p>It presents categories and tests in a tree-like layout, remembers expansion state, and
 * computes the column values that the panel renders for filtering and review.
 */
@SuppressWarnings("serial")
public class CoverageTableModel extends AbstractTableModel {

    public static final int COL_STATUS = 0;
    public static final int COL_ID = 1;
    public static final int COL_NAME = 2;
    public static final int COL_AUTO = 3;
    public static final int COL_TRIGGERED = 4;
    public static final int COL_NOTES = 5;

    private static final int COLUMN_COUNT = 6;

    private final WstgMapperData data;
    private final WstgMapperChecklistManager checklistManager;
    private final CoverageCalculator coverageCalculator;
    private final Set<String> expandedCategories = new LinkedHashSet<>();
    private final List<RowEntry> visibleRows = new ArrayList<>();

    private Predicate<WstgTest> testFilter = test -> true;
    private boolean forceExpandFilteredMatches;

    public CoverageTableModel(
            WstgMapperData data,
            WstgMapperChecklistManager checklistManager,
            CoverageCalculator coverageCalculator) {
        this.data = data;
        this.checklistManager = checklistManager;
        this.coverageCalculator = coverageCalculator;
        rebuildRows();
    }

    public void setTestFilter(Predicate<WstgTest> filter, boolean forceExpandFilteredMatches) {
        this.testFilter = filter != null ? filter : test -> true;
        this.forceExpandFilteredMatches = forceExpandFilteredMatches;
        refresh();
    }

    public void refresh() {
        rebuildRows();
        fireTableDataChanged();
    }

    public boolean isCategoryRow(int rowIndex) {
        return visibleRows.get(rowIndex) instanceof CategoryRowEntry;
    }

    public String getCategoryId(int rowIndex) {
        RowEntry row = visibleRows.get(rowIndex);
        if (row instanceof CategoryRowEntry categoryRow) {
            return categoryRow.category().getId();
        }
        return ((TestRowEntry) row).category().getId();
    }

    public WstgCategory getCategoryAt(int rowIndex) {
        RowEntry row = visibleRows.get(rowIndex);
        if (row instanceof CategoryRowEntry categoryRow) {
            return categoryRow.category();
        }
        return ((TestRowEntry) row).category();
    }

    public WstgTest getTestAt(int rowIndex) {
        RowEntry row = visibleRows.get(rowIndex);
        if (row instanceof TestRowEntry testRow) {
            return testRow.test();
        }
        return null;
    }

    public List<Integer> getTestRowsForCategory(String categoryId) {
        List<Integer> rows = new ArrayList<>();
        for (int i = 0; i < visibleRows.size(); i++) {
            RowEntry row = visibleRows.get(i);
            if (row instanceof TestRowEntry testRow
                    && testRow.category().getId().equals(categoryId)) {
                rows.add(i);
            }
        }
        return rows;
    }

    public void toggleCategory(String categoryId) {
        if (expandedCategories.contains(categoryId)) {
            expandedCategories.remove(categoryId);
        } else {
            expandedCategories.add(categoryId);
        }
        refresh();
    }

    public boolean isExpanded(String categoryId) {
        return expandedCategories.contains(categoryId);
    }

    public void expandAll() {
        for (WstgCategory category : data.getCategories()) {
            expandedCategories.add(category.getId());
        }
        refresh();
    }

    public void collapseAll() {
        expandedCategories.clear();
        refresh();
    }

    public void expandCategory(String categoryId) {
        expandedCategories.add(categoryId);
        refresh();
    }

    public void expandCategories(Set<String> categoryIds) {
        expandedCategories.addAll(categoryIds);
        refresh();
    }

    @Override
    public int getRowCount() {
        return visibleRows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public String getColumnName(int column) {
        return switch (column) {
            case COL_STATUS -> Constant.messages.getString("wstgmapper.table.col.status");
            case COL_ID -> Constant.messages.getString("wstgmapper.table.col.id");
            case COL_NAME -> Constant.messages.getString("wstgmapper.table.col.name");
            case COL_AUTO -> Constant.messages.getString("wstgmapper.table.col.auto");
            case COL_TRIGGERED -> Constant.messages.getString("wstgmapper.table.col.triggered");
            case COL_NOTES -> Constant.messages.getString("wstgmapper.table.col.notes");
            default -> "";
        };
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == COL_NOTES) {
            return String.class;
        }
        return Object.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return !isCategoryRow(rowIndex) && (columnIndex == COL_STATUS || columnIndex == COL_NOTES);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        RowEntry row = visibleRows.get(rowIndex);
        if (row instanceof CategoryRowEntry categoryRow) {
            CoverageCalculator.CategoryStats stats =
                    coverageCalculator.getCategoryStats(categoryRow.category().getId());
            return switch (columnIndex) {
                case COL_STATUS -> categoryIndicator(categoryRow.category().getId(), stats);
                case COL_ID -> categoryRow.category().getId();
                case COL_NAME -> categoryRow.category().getName();
                case COL_AUTO ->
                        stats.completedTests()
                                + "/"
                                + Math.max(0, stats.totalTests() - stats.notApplicableTests());
                case COL_TRIGGERED -> stats.completionPercent() + "%";
                case COL_NOTES -> "";
                default -> "";
            };
        }

        TestRowEntry testRow = (TestRowEntry) row;
        WstgTest test = testRow.test();
        return switch (columnIndex) {
            case COL_STATUS -> checklistManager.getTestStatus(test.getId());
            case COL_ID -> test.getId();
            case COL_NAME -> test.getName();
            case COL_AUTO -> coverageCalculator.isAutomated(test.getId());
            case COL_TRIGGERED -> checklistManager.isTriggered(test.getId());
            case COL_NOTES -> checklistManager.getTestNotes(test.getId());
            default -> "";
        };
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex) {
        WstgTest test = getTestAt(rowIndex);
        if (test == null) {
            return;
        }
        if (columnIndex == COL_STATUS && value instanceof WstgTestStatus status) {
            checklistManager.setTestStatus(test.getId(), status);
        } else if (columnIndex == COL_NOTES && value instanceof String notes) {
            checklistManager.setTestNotes(test.getId(), notes);
        }
    }

    private void rebuildRows() {
        visibleRows.clear();
        boolean hasExplicitFilter = forceExpandFilteredMatches;
        for (WstgCategory category : data.getCategories()) {
            List<WstgTest> matchingTests = new ArrayList<>();
            if (category.getTests() != null) {
                for (WstgTest test : category.getTests()) {
                    if (testFilter.test(test)) {
                        matchingTests.add(test);
                    }
                }
            }
            if (matchingTests.isEmpty() && hasExplicitFilter) {
                continue;
            }

            visibleRows.add(new CategoryRowEntry(category));
            boolean showChildren =
                    expandedCategories.contains(category.getId()) || forceExpandFilteredMatches;
            if (showChildren) {
                for (WstgTest test : matchingTests) {
                    visibleRows.add(new TestRowEntry(category, test));
                }
            }
        }
    }

    private String categoryIndicator(String categoryId, CoverageCalculator.CategoryStats stats) {
        String expanded =
                expandedCategories.contains(categoryId) || forceExpandFilteredMatches ? "▼" : "▶";
        String state = stats.isCompleted() ? "✅" : stats.isInProgress() ? "◐" : "○";
        return expanded + " " + state;
    }

    private sealed interface RowEntry permits CategoryRowEntry, TestRowEntry {}

    private record CategoryRowEntry(WstgCategory category) implements RowEntry {}

    private record TestRowEntry(WstgCategory category, WstgTest test) implements RowEntry {}
}
