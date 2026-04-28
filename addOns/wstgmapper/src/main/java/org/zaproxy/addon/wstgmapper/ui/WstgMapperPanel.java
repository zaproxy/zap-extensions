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

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.addon.wstgmapper.CoverageCalculator;
import org.zaproxy.addon.wstgmapper.ExtensionWstgMapper;
import org.zaproxy.addon.wstgmapper.ReportGenerator;
import org.zaproxy.addon.wstgmapper.TechStackDetector;
import org.zaproxy.addon.wstgmapper.WstgMapperChecklistManager;
import org.zaproxy.addon.wstgmapper.WstgMapperChecklistManager.WstgMapperListener;
import org.zaproxy.addon.wstgmapper.WstgMapperData;
import org.zaproxy.addon.wstgmapper.WstgMapperMappingManager;
import org.zaproxy.addon.wstgmapper.model.WstgCategory;
import org.zaproxy.addon.wstgmapper.model.WstgTest;
import org.zaproxy.addon.wstgmapper.model.WstgTestStatus;

/**
 * Main dashboard panel for the WSTG Mapper add-on.
 *
 * <p>It wires together the filters, summary widgets, table model, detail panel, and export actions
 * so a tester can review WSTG coverage from one place inside the ZAP workbench.
 */
@SuppressWarnings("serial")
public class WstgMapperPanel extends AbstractPanel implements WstgMapperListener {

    private enum FilterMode {
        ALL,
        TRIGGERED_ONLY,
        NOT_TRIGGERED,
        MANUAL_ONLY,
        FAILED,
        NOT_APPLICABLE,
        COMPLETED_CATEGORIES,
        INCOMPLETE_CATEGORIES
    }

    private final WstgMapperData data;
    private final WstgMapperMappingManager mappingManager;
    private final WstgMapperChecklistManager checklistManager;
    private final CoverageCalculator coverageCalculator;
    private final TechStackDetector techStackDetector;
    private final ReportGenerator reportGenerator;

    private final Map<String, WstgCategory> categoriesById = new HashMap<>();
    private final Map<String, String> categoryIdByTest = new HashMap<>();
    private final List<String> categorySelectionIds = new ArrayList<>();

    private CoverageTableModel tableModel;
    private JTable table;
    private WstgDetailPanel detailPanel;
    private JTextField searchField;
    private JComboBox<String> filterCombo;
    private JComboBox<String> categoryCombo;
    private JComboBox<String> techCombo;
    private JProgressBar coverageBar;
    private WstgMapperExporter exporter;
    private Set<String> techRelevantTests = Set.of();

    public WstgMapperPanel(
            WstgMapperData data,
            WstgMapperMappingManager mappingManager,
            WstgMapperChecklistManager checklistManager,
            CoverageCalculator coverageCalculator,
            TechStackDetector techStackDetector) {
        this.data = data;
        this.mappingManager = mappingManager;
        this.checklistManager = checklistManager;
        this.coverageCalculator = coverageCalculator;
        this.techStackDetector = techStackDetector;
        this.reportGenerator = new ReportGenerator();
        this.exporter =
                new WstgMapperExporter(
                        reportGenerator,
                        data,
                        mappingManager,
                        checklistManager,
                        coverageCalculator);
        indexData();
        initialise();
        checklistManager.addListener(this);
    }

    private void indexData() {
        for (WstgCategory category : data.getCategories()) {
            categoriesById.put(category.getId(), category);
            if (category.getTests() == null) {
                continue;
            }
            for (WstgTest test : category.getTests()) {
                categoryIdByTest.put(test.getId(), category.getId());
            }
        }
    }

    private void initialise() {
        setName(Constant.messages.getString("wstgmapper.panel.title"));
        var icon = ExtensionWstgMapper.getIcon();
        if (icon != null) {
            setIcon(icon);
        }
        setLayout(new BorderLayout());

        add(buildToolBar(), BorderLayout.NORTH);

        tableModel = new CoverageTableModel(data, checklistManager, coverageCalculator);
        table = buildTable();
        detailPanel = new WstgDetailPanel(checklistManager);

        JSplitPane splitPane =
                new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(table), detailPanel);
        splitPane.setResizeWeight(0.62);
        splitPane.setDividerSize(6);
        add(splitPane, BorderLayout.CENTER);

        refreshTable();
    }

    private JToolBar buildToolBar() {
        JToolBar toolBar = new JToolBar();
        toolBar.setFloatable(false);

        filterCombo =
                new JComboBox<>(
                        new String[] {
                            Constant.messages.getString("wstgmapper.filter.all"),
                            Constant.messages.getString("wstgmapper.filter.triggered"),
                            Constant.messages.getString("wstgmapper.filter.notTriggered"),
                            Constant.messages.getString("wstgmapper.filter.manualOnly"),
                            Constant.messages.getString("wstgmapper.filter.failed"),
                            Constant.messages.getString("wstgmapper.filter.notApplicable"),
                            Constant.messages.getString("wstgmapper.filter.completedCategories"),
                            Constant.messages.getString("wstgmapper.filter.incompleteCategories")
                        });
        filterCombo.addActionListener(e -> refreshTable());

        categorySelectionIds.add(null);
        List<String> categoryLabels = new ArrayList<>();
        categoryLabels.add(Constant.messages.getString("wstgmapper.category.all"));
        for (WstgCategory category : data.getCategories()) {
            categorySelectionIds.add(category.getId());
            categoryLabels.add(category.getName() + " (" + category.getId() + ")");
        }
        categoryCombo = new JComboBox<>(categoryLabels.toArray(String[]::new));
        categoryCombo.addActionListener(e -> refreshTable());

        techCombo =
                new JComboBox<>(
                        new String[] {
                            Constant.messages.getString("wstgmapper.tech.all"),
                            Constant.messages.getString("wstgmapper.tech.detected")
                        });
        techCombo.addActionListener(e -> refreshTable());

        searchField = new JTextField(18);
        searchField.setToolTipText(Constant.messages.getString("wstgmapper.filter.search.tooltip"));
        searchField
                .getDocument()
                .addDocumentListener(
                        new DocumentListener() {
                            @Override
                            public void insertUpdate(DocumentEvent e) {
                                refreshTable();
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e) {
                                refreshTable();
                            }

                            @Override
                            public void changedUpdate(DocumentEvent e) {
                                refreshTable();
                            }
                        });

        JButton expandButton =
                new JButton(Constant.messages.getString("wstgmapper.button.expandAll"));
        expandButton.addActionListener(e -> tableModel.expandAll());

        JButton collapseButton =
                new JButton(Constant.messages.getString("wstgmapper.button.collapseAll"));
        collapseButton.addActionListener(e -> tableModel.collapseAll());

        JButton exportButton = new JButton(Constant.messages.getString("wstgmapper.button.export"));
        JPopupMenu exportMenu = buildExportMenu(exportButton);
        exportButton.addActionListener(
                e -> exportMenu.show(exportButton, 0, exportButton.getHeight()));

        coverageBar = new JProgressBar(0, 100);
        coverageBar.setStringPainted(true);
        coverageBar.setToolTipText(Constant.messages.getString("wstgmapper.coverage.tooltip"));
        coverageBar.addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        expandIncompleteCategories();
                    }
                });

        toolBar.add(new JLabel(Constant.messages.getString("wstgmapper.filter.label") + " "));
        toolBar.add(filterCombo);
        toolBar.addSeparator();
        toolBar.add(new JLabel(Constant.messages.getString("wstgmapper.category.label") + " "));
        toolBar.add(categoryCombo);
        toolBar.addSeparator();
        toolBar.add(new JLabel(Constant.messages.getString("wstgmapper.tech.label") + " "));
        toolBar.add(techCombo);
        toolBar.addSeparator();
        toolBar.add(new JLabel(Constant.messages.getString("wstgmapper.filter.search") + " "));
        toolBar.add(searchField);
        toolBar.addSeparator();
        toolBar.add(expandButton);
        toolBar.add(collapseButton);
        toolBar.add(exportButton);
        toolBar.addSeparator();
        toolBar.add(coverageBar);

        return toolBar;
    }

    private JPopupMenu buildExportMenu(JButton exportButton) {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem exportMarkdown =
                new JMenuItem(Constant.messages.getString("wstgmapper.button.export.markdown"));
        exportMarkdown.addActionListener(e -> exporter.exportMarkdown(this));
        menu.add(exportMarkdown);

        JMenuItem exportCsv =
                new JMenuItem(Constant.messages.getString("wstgmapper.button.export.csv"));
        exportCsv.addActionListener(e -> exporter.exportCsv(this));
        menu.add(exportCsv);

        return menu;
    }

    private JTable buildTable() {
        JTable checklistTable = new JTable(tableModel);
        checklistTable.setRowSelectionAllowed(true);
        checklistTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        checklistTable.setFillsViewportHeight(true);
        checklistTable
                .getSelectionModel()
                .addListSelectionListener(
                        e -> {
                            if (!e.getValueIsAdjusting() && detailPanel != null) {
                                int selectedRow = checklistTable.getSelectedRow();
                                detailPanel.showTest(
                                        selectedRow >= 0
                                                ? tableModel.getTestAt(selectedRow)
                                                : null);
                            }
                        });

        TableColumn statusColumn =
                checklistTable.getColumnModel().getColumn(CoverageTableModel.COL_STATUS);
        TableColumn autoColumn =
                checklistTable.getColumnModel().getColumn(CoverageTableModel.COL_AUTO);
        TableColumn triggeredColumn =
                checklistTable.getColumnModel().getColumn(CoverageTableModel.COL_TRIGGERED);

        statusColumn.setCellEditor(new DefaultCellEditor(new JComboBox<>(WstgTestStatus.values())));
        statusColumn.setCellRenderer(new StatusRenderer());
        autoColumn.setCellRenderer(new AutoTriggeredRenderer(CoverageTableModel.COL_AUTO));
        triggeredColumn.setCellRenderer(
                new AutoTriggeredRenderer(CoverageTableModel.COL_TRIGGERED));
        checklistTable
                .getColumnModel()
                .getColumn(CoverageTableModel.COL_NAME)
                .setCellRenderer(new NameRenderer());
        checklistTable
                .getColumnModel()
                .getColumn(CoverageTableModel.COL_ID)
                .setCellRenderer(new BaseRenderer());
        checklistTable
                .getColumnModel()
                .getColumn(CoverageTableModel.COL_NOTES)
                .setCellRenderer(new BaseRenderer());

        statusColumn.setPreferredWidth(90);
        autoColumn.setPreferredWidth(75);
        triggeredColumn.setPreferredWidth(85);

        JPopupMenu testMenu = buildTestMenu();
        JPopupMenu categoryMenu = buildCategoryMenu();

        checklistTable.addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        int row = checklistTable.rowAtPoint(e.getPoint());
                        if (row < 0) {
                            return;
                        }

                        if (tableModel.isCategoryRow(row)) {
                            if (e.getClickCount() >= 2) {
                                expandAndFocusCategory(tableModel.getCategoryId(row));
                            } else if (SwingUtilities.isLeftMouseButton(e)) {
                                tableModel.toggleCategory(tableModel.getCategoryId(row));
                            }
                            return;
                        }

                        if (e.getClickCount() >= 2) {
                            detailPanel.openCurrentReference();
                        }
                    }

                    @Override
                    public void mousePressed(MouseEvent e) {
                        maybeShowPopup(e);
                    }

                    @Override
                    public void mouseReleased(MouseEvent e) {
                        maybeShowPopup(e);
                    }

                    private void maybeShowPopup(MouseEvent e) {
                        if (!e.isPopupTrigger()) {
                            return;
                        }
                        int row = checklistTable.rowAtPoint(e.getPoint());
                        if (row < 0) {
                            return;
                        }
                        checklistTable.setRowSelectionInterval(row, row);
                        if (tableModel.isCategoryRow(row)) {
                            categoryMenu.show(checklistTable, e.getX(), e.getY());
                        } else {
                            testMenu.show(checklistTable, e.getX(), e.getY());
                        }
                    }
                });

        return checklistTable;
    }

    private JPopupMenu buildTestMenu() {
        JPopupMenu menu = new JPopupMenu();
        menu.add(
                statusItem(
                        Constant.messages.getString("wstgmapper.menu.markPassed"),
                        WstgTestStatus.PASSED));
        menu.add(
                statusItem(
                        Constant.messages.getString("wstgmapper.menu.markFailed"),
                        WstgTestStatus.FAILED));
        menu.add(
                statusItem(
                        Constant.messages.getString("wstgmapper.menu.markManual"),
                        WstgTestStatus.MANUAL_ONLY));
        menu.add(
                statusItem(
                        Constant.messages.getString("wstgmapper.menu.markNotApplicable"),
                        WstgTestStatus.NOT_APPLICABLE));
        menu.add(
                statusItem(
                        Constant.messages.getString("wstgmapper.menu.markNotTested"),
                        WstgTestStatus.NOT_TESTED));

        JMenuItem openReference =
                new JMenuItem(Constant.messages.getString("wstgmapper.menu.openReference"));
        openReference.addActionListener(e -> detailPanel.openCurrentReference());
        menu.add(openReference);
        return menu;
    }

    private JMenuItem statusItem(String label, WstgTestStatus status) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(
                e -> {
                    WstgTest test = tableModel.getTestAt(table.getSelectedRow());
                    if (test != null) {
                        checklistManager.setTestStatus(test.getId(), status);
                    }
                });
        return item;
    }

    private JPopupMenu buildCategoryMenu() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem expand = new JMenuItem(Constant.messages.getString("wstgmapper.menu.expand"));
        expand.addActionListener(e -> tableModel.expandCategory(selectedCategoryId()));
        menu.add(expand);

        JMenuItem collapse = new JMenuItem(Constant.messages.getString("wstgmapper.menu.collapse"));
        collapse.addActionListener(
                e -> {
                    String categoryId = selectedCategoryId();
                    if (categoryId != null && tableModel.isExpanded(categoryId)) {
                        tableModel.toggleCategory(categoryId);
                    }
                });
        menu.add(collapse);

        JMenuItem markNa =
                new JMenuItem(Constant.messages.getString("wstgmapper.menu.markCategoryNa"));
        markNa.addActionListener(
                e -> {
                    WstgCategory category = categoriesById.get(selectedCategoryId());
                    if (category != null && category.getTests() != null) {
                        for (WstgTest test : category.getTests()) {
                            checklistManager.setTestStatus(
                                    test.getId(), WstgTestStatus.NOT_APPLICABLE);
                        }
                    }
                });
        menu.add(markNa);

        JMenuItem exportCategory =
                new JMenuItem(Constant.messages.getString("wstgmapper.menu.exportCategory"));
        exportCategory.addActionListener(
                e -> {
                    WstgCategory category = categoriesById.get(selectedCategoryId());
                    if (category != null) {
                        exporter.exportCategoryMarkdown(this, category);
                    }
                });
        menu.add(exportCategory);

        JMenuItem exportCategoryCsv =
                new JMenuItem(Constant.messages.getString("wstgmapper.menu.exportCategoryCsv"));
        exportCategoryCsv.addActionListener(
                e -> {
                    WstgCategory category = categoriesById.get(selectedCategoryId());
                    if (category != null) {
                        exporter.exportCategoryCsv(this, category);
                    }
                });
        menu.add(exportCategoryCsv);

        return menu;
    }

    private void refreshTable() {
        techRelevantTests = techStackDetector.getRelevantTestIds(checklistManager);

        String selectedCategoryId = categorySelectionIds.get(categoryCombo.getSelectedIndex());
        String query = searchField.getText().trim().toLowerCase();
        FilterMode filterMode = FilterMode.values()[filterCombo.getSelectedIndex()];
        boolean detectedOnly = techCombo.getSelectedIndex() == 1;

        Predicate<WstgTest> predicate =
                test -> {
                    String categoryId = categoryIdByTest.get(test.getId());
                    if (selectedCategoryId != null && !selectedCategoryId.equals(categoryId)) {
                        return false;
                    }
                    if (detectedOnly && !techRelevantTests.contains(test.getId())) {
                        return false;
                    }
                    if (!query.isBlank()) {
                        String normalizedName =
                                test.getName() != null ? test.getName().toLowerCase() : "";
                        if (!test.getId().toLowerCase().contains(query)
                                && !normalizedName.contains(query)) {
                            return false;
                        }
                    }
                    return matchesFilterMode(test, categoryId, filterMode);
                };

        boolean filterActive =
                selectedCategoryId != null
                        || detectedOnly
                        || filterMode != FilterMode.ALL
                        || !query.isBlank();

        tableModel.setTestFilter(predicate, filterActive);
        updateCoverageBar();
    }

    private boolean matchesFilterMode(WstgTest test, String categoryId, FilterMode filterMode) {
        return switch (filterMode) {
            case ALL -> true;
            case TRIGGERED_ONLY -> checklistManager.isTriggered(test.getId());
            case NOT_TRIGGERED -> !checklistManager.isTriggered(test.getId());
            case MANUAL_ONLY -> !coverageCalculator.isAutomated(test.getId());
            case FAILED -> checklistManager.getTestStatus(test.getId()) == WstgTestStatus.FAILED;
            case NOT_APPLICABLE ->
                    checklistManager.getTestStatus(test.getId()) == WstgTestStatus.NOT_APPLICABLE;
            case COMPLETED_CATEGORIES ->
                    coverageCalculator.getCategoryStats(categoryId).isCompleted();
            case INCOMPLETE_CATEGORIES ->
                    !coverageCalculator.getCategoryStats(categoryId).isCompleted();
        };
    }

    private void updateCoverageBar() {
        int totalCategories = coverageCalculator.getTotalCategories();
        if (totalCategories == 0) {
            coverageBar.setValue(0);
            coverageBar.setString(Constant.messages.getString("wstgmapper.coverage.none"));
            return;
        }

        double percent = coverageCalculator.getCategoryCoveragePercentage();
        coverageBar.setValue((int) Math.round(percent));
        coverageBar.setString(
                Constant.messages.getString(
                        "wstgmapper.coverage.summary",
                        percent,
                        coverageCalculator.getCompletedCategoryCount(),
                        totalCategories));
    }

    private void expandIncompleteCategories() {
        Set<String> incomplete = new LinkedHashSet<>();
        for (CoverageCalculator.CategoryStats stats : coverageCalculator.getAllCategoryStats()) {
            if (!stats.isCompleted()) {
                incomplete.add(stats.categoryId());
            }
        }
        tableModel.expandCategories(incomplete);
        if (!incomplete.isEmpty()) {
            expandAndFocusCategory(incomplete.iterator().next());
        }
    }

    private void expandAndFocusCategory(String categoryId) {
        tableModel.expandCategory(categoryId);
        for (int row : tableModel.getTestRowsForCategory(categoryId)) {
            WstgTest test = tableModel.getTestAt(row);
            if (test != null && isIncompleteTest(test)) {
                table.setRowSelectionInterval(row, row);
                table.scrollRectToVisible(table.getCellRect(row, 0, true));
                return;
            }
        }
    }

    private String selectedCategoryId() {
        int row = table.getSelectedRow();
        return row >= 0 ? tableModel.getCategoryId(row) : null;
    }

    @Override
    public void changed() {
        SwingUtilities.invokeLater(
                () -> {
                    refreshTable();
                    detailPanel.refreshCurrentTest();
                });
    }

    public void cleanup() {
        if (detailPanel != null) {
            detailPanel.cleanup();
        }
    }

    private class BaseRenderer extends DefaultTableCellRenderer {

        @Override
        public Component getTableCellRendererComponent(
                JTable table,
                Object value,
                boolean isSelected,
                boolean hasFocus,
                int row,
                int column) {
            Component component =
                    super.getTableCellRendererComponent(
                            table, value, isSelected, hasFocus, row, column);
            styleComponent(component, row, isSelected);
            if (tableModel.isCategoryRow(row)) {
                setFont(getFont().deriveFont(Font.BOLD));
            }
            return component;
        }
    }

    private class NameRenderer extends BaseRenderer {

        @Override
        public Component getTableCellRendererComponent(
                JTable table,
                Object value,
                boolean isSelected,
                boolean hasFocus,
                int row,
                int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (tableModel.isCategoryRow(row)) {
                WstgCategory category = tableModel.getCategoryAt(row);
                CoverageCalculator.CategoryStats stats =
                        coverageCalculator.getCategoryStats(category.getId());
                setText(
                        category.getName()
                                + " ("
                                + category.getId()
                                + ")  "
                                + stats.completedTests()
                                + "/"
                                + Math.max(0, stats.totalTests() - stats.notApplicableTests())
                                + "  "
                                + stats.completionPercent()
                                + "%");
            }
            return this;
        }
    }

    private class StatusRenderer extends BaseRenderer {

        @Override
        public Component getTableCellRendererComponent(
                JTable table,
                Object value,
                boolean isSelected,
                boolean hasFocus,
                int row,
                int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setHorizontalAlignment(SwingConstants.CENTER);
            if (tableModel.isCategoryRow(row)) {
                setText(String.valueOf(value));
                return this;
            }

            WstgTest test = tableModel.getTestAt(row);
            setText(statusIcon(test));
            return this;
        }
    }

    private class AutoTriggeredRenderer extends BaseRenderer {

        private final int column;

        private AutoTriggeredRenderer(int column) {
            this.column = column;
            setHorizontalAlignment(SwingConstants.CENTER);
        }

        @Override
        public Component getTableCellRendererComponent(
                JTable table,
                Object value,
                boolean isSelected,
                boolean hasFocus,
                int row,
                int columnIndex) {
            super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, columnIndex);
            setHorizontalAlignment(SwingConstants.CENTER);
            if (tableModel.isCategoryRow(row)) {
                setText(value != null ? String.valueOf(value) : "");
                return this;
            }
            boolean enabled = Boolean.TRUE.equals(value);
            setText(
                    column == CoverageTableModel.COL_TRIGGERED
                            ? (enabled ? "●" : "○")
                            : (enabled ? "✓" : "✕"));
            return this;
        }
    }

    private void styleComponent(Component component, int row, boolean selected) {
        if (selected) {
            component.setForeground(table.getSelectionForeground());
            component.setBackground(table.getSelectionBackground());
            return;
        }

        component.setForeground(Color.BLACK);
        if (tableModel.isCategoryRow(row)) {
            CoverageCalculator.CategoryStats stats =
                    coverageCalculator.getCategoryStats(tableModel.getCategoryId(row));
            if (stats.isCompleted()) {
                component.setBackground(new Color(218, 247, 220));
            } else if (stats.isInProgress()) {
                component.setBackground(new Color(255, 248, 212));
            } else {
                component.setBackground(Color.WHITE);
            }
            return;
        }

        WstgTest test = tableModel.getTestAt(row);
        WstgTestStatus status = checklistManager.getTestStatus(test.getId());
        if (status == WstgTestStatus.FAILED) {
            component.setBackground(new Color(255, 228, 228));
        } else if (checklistManager.isTriggered(test.getId())) {
            component.setBackground(new Color(227, 247, 233));
        } else if (techRelevantTests.contains(test.getId())) {
            component.setBackground(new Color(229, 240, 255));
        } else {
            component.setBackground(Color.WHITE);
        }
    }

    private String statusIcon(WstgTest test) {
        WstgTestStatus status = checklistManager.getTestStatus(test.getId());
        if (status == WstgTestStatus.PASSED) {
            return "✅";
        }
        if (status == WstgTestStatus.FAILED) {
            return "❌";
        }
        if (status == WstgTestStatus.MANUAL_ONLY) {
            return "⚠";
        }
        if (status == WstgTestStatus.NOT_APPLICABLE) {
            return "⚪";
        }
        return checklistManager.isTriggered(test.getId()) ? "●" : "○";
    }

    private boolean isIncompleteTest(WstgTest test) {
        WstgTestStatus status = checklistManager.getTestStatus(test.getId());
        if (status == WstgTestStatus.NOT_APPLICABLE) {
            return false;
        }
        if (status == WstgTestStatus.FAILED || status == WstgTestStatus.MANUAL_ONLY) {
            return true;
        }
        return status == WstgTestStatus.NOT_TESTED && !checklistManager.isTriggered(test.getId());
    }
}
