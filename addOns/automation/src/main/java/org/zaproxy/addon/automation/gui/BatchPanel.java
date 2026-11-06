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
package org.zaproxy.addon.automation.gui;

import java.awt.GridBagLayout;
import java.awt.event.MouseEvent;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.PlanBatch;
import org.zaproxy.addon.automation.PlanBatch.Status;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.view.LayoutHelper;

/**
 * The panel which runs all, or one, of the plans in a directory, one after the other, stopping at
 * the first one that fails.
 *
 * <p>Each plan is shown in the plan panel when it is run, this panel only shows the summary.
 */
@SuppressWarnings("serial")
class BatchPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private static final ImageIcon RUN_ALL_ICON =
            DisplayUtils.getScaledIcon(
                    BatchPanel.class.getResource(
                            ExtensionAutomation.RESOURCES_DIR + "control-double.png"));
    private static final ImageIcon RUN_SELECTED_ICON =
            DisplayUtils.getScaledIcon(
                    BatchPanel.class.getResource(
                            ExtensionAutomation.RESOURCES_DIR + "run-selected.png"));
    private static final ImageIcon STOP_ICON =
            DisplayUtils.getScaledIcon(BatchPanel.class.getResource("/resource/icon/16/142.png"));
    private static final ImageIcon BROWSE_ICON =
            DisplayUtils.getScaledIcon(BatchPanel.class.getResource("/resource/icon/16/047.png"));

    private static final int DIRECTORY_FIELD_COLUMNS = 40;

    private final ExtensionAutomation ext;
    private final BooleanSupplier refuseUnsavedChanges;
    private final Runnable runningChanged;
    private final BatchTableModel model = new BatchTableModel();

    private JTextField directoryField;
    private JButton browseButton;
    private JButton runAllButton;
    private JButton runSelectedButton;
    private JButton stopButton;
    private JXTable table;
    private JLabel summaryLabel;

    private volatile PlanBatch batch;
    private volatile AutomationPlan finishedPlan;

    /**
     * Constructs a panel.
     *
     * @param ext the extension, used to load and run the plans.
     * @param refuseUnsavedChanges tells if the user refused to lose the changes of the plan
     *     currently shown, which is replaced by the plans run.
     * @param runningChanged called, on the event dispatch thread, when a batch starts or finishes.
     */
    BatchPanel(
            ExtensionAutomation ext,
            BooleanSupplier refuseUnsavedChanges,
            Runnable runningChanged) {
        this.ext = ext;
        this.refuseUnsavedChanges = refuseUnsavedChanges;
        this.runningChanged = runningChanged;

        setLayout(new GridBagLayout());
        add(getToolbar(), LayoutHelper.getGBC(0, 0, 1, 1.0));
        add(new JScrollPane(getTable()), LayoutHelper.getGBC(0, 1, 1, 1.0, 1.0));
        add(getSummaryLabel(), LayoutHelper.getGBC(0, 2, 1, 1.0));

        String directory = ext.getParam().getBatchDirectory();
        if (StringUtils.isNotEmpty(directory)) {
            directoryField.setText(directory);
            loadPlans();
        } else {
            updateButtons();
        }
    }

    private JToolBar getToolbar() {
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);

        runAllButton = new JButton(RUN_ALL_ICON);
        runAllButton.setToolTipText(Constant.messages.getString("automation.batch.run.all"));
        runAllButton.addActionListener(e -> run(model.getFiles()));
        toolbar.add(runAllButton);

        runSelectedButton = new JButton(RUN_SELECTED_ICON);
        runSelectedButton.setToolTipText(
                Constant.messages.getString("automation.batch.run.selected"));
        runSelectedButton.addActionListener(e -> run(getSelectedFiles()));
        toolbar.add(runSelectedButton);

        stopButton = new JButton(STOP_ICON);
        stopButton.setToolTipText(Constant.messages.getString("automation.batch.stop"));
        stopButton.addActionListener(e -> stop());
        toolbar.add(stopButton);

        toolbar.addSeparator();
        toolbar.add(new JLabel(Constant.messages.getString("automation.batch.dir")));

        directoryField = new JTextField(DIRECTORY_FIELD_COLUMNS);
        directoryField.setToolTipText(Constant.messages.getString("automation.batch.dir.tooltip"));
        directoryField.addActionListener(e -> loadPlans());
        // Stops the toolbar stretching the field to fill the extra space.
        directoryField.setMaximumSize(directoryField.getPreferredSize());
        toolbar.add(directoryField);

        browseButton = new JButton(BROWSE_ICON);
        browseButton.setToolTipText(Constant.messages.getString("automation.batch.browse"));
        browseButton.addActionListener(e -> browse());
        toolbar.add(browseButton);
        return toolbar;
    }

    private JTable getTable() {
        if (table == null) {
            table =
                    new JXTable(model) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public String getToolTipText(MouseEvent event) {
                            int row = rowAtPoint(event.getPoint());
                            if (row < 0) {
                                return null;
                            }
                            List<String> errors = model.getErrors(convertRowIndexToModel(row));
                            return errors.isEmpty()
                                    ? null
                                    : "<html>"
                                            + String.join(
                                                    "<br>",
                                                    errors.stream()
                                                            .map(StringEscapeUtils::escapeHtml4)
                                                            .toList());
                        }
                    };
            table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            table.getSelectionModel().addListSelectionListener(e -> updateButtons());
            table.setColumnControlVisible(true);
        }
        return table;
    }

    private JLabel getSummaryLabel() {
        if (summaryLabel == null) {
            summaryLabel = new JLabel(Constant.messages.getString("automation.batch.summary.none"));
        }
        return summaryLabel;
    }

    private List<File> getSelectedFiles() {
        List<File> files = new ArrayList<>();
        for (int row : table.getSelectedRows()) {
            files.add(model.getFile(table.convertRowIndexToModel(row)));
        }
        return files;
    }

    private void browse() {
        String current = directoryField.getText();
        JFileChooser chooser =
                new JFileChooser(
                        StringUtils.isNotEmpty(current)
                                ? current
                                : ext.getParam().getPlanDirectory());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (chooser.showOpenDialog(View.getSingleton().getMainFrame())
                == JFileChooser.APPROVE_OPTION) {
            directoryField.setText(chooser.getSelectedFile().getAbsolutePath());
            loadPlans();
        }
    }

    private void loadPlans() {
        if (batch != null) {
            return;
        }
        String directory = directoryField.getText().trim();
        List<File> files = PlanBatch.listPlans(new File(directory));
        model.setFiles(files);
        if (!directory.isEmpty()) {
            ext.getParam().setBatchDirectory(directory);
        }
        if (files.isEmpty()) {
            summaryLabel.setText(
                    directory.isEmpty()
                            ? Constant.messages.getString("automation.batch.summary.none")
                            : Constant.messages.getString("automation.batch.noplans", directory));
        } else {
            summaryLabel.setText(" ");
        }
        updateButtons();
    }

    private void updateButtons() {
        boolean running = batch != null;
        boolean canRun = !running && !isPlanRunning();
        boolean hasPlans = model.getRowCount() > 0;
        directoryField.setEnabled(!running);
        browseButton.setEnabled(!running);
        runAllButton.setEnabled(canRun && hasPlans);
        runSelectedButton.setEnabled(canRun && table.getSelectedRowCount() > 0);
        stopButton.setEnabled(running);
    }

    /** Tells if a plan, other than a plan of a batch, is being run. */
    private boolean isPlanRunning() {
        return batch == null
                && ext.getRunningPlans().stream().anyMatch(plan -> plan != finishedPlan);
    }

    /**
     * Called when a plan has started or finished, so that the batch cannot be run at the same time
     * as a plan.
     *
     * @param finished the plan that finished, which is still listed as running when this is called,
     *     or {@code null} if a plan started.
     */
    void planRunningChanged(AutomationPlan finished) {
        finishedPlan = finished;
        SwingUtilities.invokeLater(this::updateButtons);
    }

    private void run(List<File> files) {
        if (batch != null
                || isPlanRunning()
                || files.isEmpty()
                || refuseUnsavedChanges.getAsBoolean()) {
            return;
        }
        PlanBatch newBatch = new PlanBatch(files, ext::loadPlan, this::runPlan);
        newBatch.setListener(entry -> SwingUtilities.invokeLater(() -> update(newBatch, entry)));
        model.reset(files);
        batch = newBatch;
        updateButtons();
        runningChanged.run();

        Thread thread =
                new Thread(
                        () -> {
                            try {
                                newBatch.run();
                            } finally {
                                SwingUtilities.invokeLater(() -> finished(newBatch));
                            }
                        },
                        "ZAP-Automation-Batch");
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Clears the stats, as many plans rely on them, shows the plan in the plan panel and runs it,
     * called from the thread running the batch.
     */
    private AutomationProgress runPlan(AutomationPlan plan) {
        Stats.clearAll();
        try {
            SwingUtilities.invokeAndWait(() -> ext.displayPlan(plan));
        } catch (InvocationTargetException e) {
            throw new IllegalStateException(e.getCause());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
        // The progress is not reset, to keep any errors found when the plan was loaded.
        return ext.runPlan(plan, false);
    }

    /** Tells if a batch is being run. */
    boolean isRunning() {
        return batch != null;
    }

    /** Stops the batch, including the plan currently running, if any. */
    void stop() {
        PlanBatch current = batch;
        if (current != null) {
            current.stop();
        }
    }

    private void update(PlanBatch current, PlanBatch.Entry entry) {
        model.update(entry);
        if (entry.getStatus() == Status.RUNNING) {
            int index = current.getEntries().indexOf(entry) + 1;
            summaryLabel.setText(
                    Constant.messages.getString(
                            "automation.batch.summary.running",
                            index,
                            current.getEntries().size(),
                            entry.getFile().getName()));
        }
    }

    private void finished(PlanBatch current) {
        batch = null;
        updateButtons();
        runningChanged.run();

        List<PlanBatch.Entry> entries = current.getEntries();
        long run = entries.stream().filter(e -> e.getStatus() != Status.NOT_RUN).count();
        PlanBatch.Entry problem =
                entries.stream()
                        .filter(
                                e ->
                                        e.getStatus() == Status.FAIL
                                                || e.getStatus() == Status.LOAD_ERROR
                                                || e.getStatus() == Status.STOPPED)
                        .findFirst()
                        .orElse(null);
        if (problem == null) {
            summaryLabel.setText(
                    Constant.messages.getString("automation.batch.summary.pass", entries.size()));
            return;
        }
        summaryLabel.setText(
                Constant.messages.getString(
                        problem.getStatus() == Status.STOPPED
                                ? "automation.batch.summary.stopped"
                                : "automation.batch.summary.fail",
                        problem.getFile().getName(),
                        run,
                        entries.size()));
        int row = model.getFirstProblemRow();
        if (row >= 0) {
            int viewRow = table.convertRowIndexToView(row);
            table.getSelectionModel().setSelectionInterval(viewRow, viewRow);
        }
    }
}
