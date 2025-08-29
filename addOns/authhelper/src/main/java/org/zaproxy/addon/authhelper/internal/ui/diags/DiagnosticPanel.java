/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal.ui.diags;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JToolBar;
import javax.swing.SortOrder;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticStep;
import org.zaproxy.addon.authhelper.internal.db.TableJdo;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.TabbedPanel2;
import org.zaproxy.zap.view.ZapTable;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

@SuppressWarnings("serial")
public class DiagnosticPanel extends AbstractPanel {

    private static final Logger LOGGER = LogManager.getLogger(DiagnosticPanel.class);

    private static final long serialVersionUID = 1L;

    private final List<StepUi> steps;

    private File currentScreenshotDirectory;

    public DiagnosticPanel(String name, DiagnosticUi diagnostic) {
        setName(name);
        setLayout(new BorderLayout());

        steps = readSteps(diagnostic);

        TabbedPanel2 tabbedPane = new TabbedPanel2();

        addStepsTab(tabbedPane, steps);
        addScreenshotsTab(tabbedPane, diagnostic, steps);
        addScriptTab(tabbedPane, diagnostic);

        add(tabbedPane, BorderLayout.CENTER);
    }

    private static void addStepsTab(TabbedPanel2 mainTabbedPane, List<StepUi> steps) {
        Map<String, JPanel> stepsPanels = new HashMap<>();

        StepsTableModel model = new StepsTableModel(steps);
        JTabbedPane stepsTabbedPane = createLeftTabbedPane();
        ZapTable stepsTable = new ZapTable();
        stepsTable.setModel(model);
        stepsTable.addMouseListener(
                new MouseAdapter() {

                    @Override
                    public void mousePressed(MouseEvent e) {
                        if (e.getClickCount() >= 2) {
                            int row = stepsTable.rowAtPoint(e.getPoint());
                            if (row >= 0) {
                                StepUi step = model.getStep(stepsTable.convertRowIndexToModel(row));
                                JPanel stepPanel = stepsPanels.get(step.getLabel());

                                stepsTabbedPane.setSelectedComponent(stepPanel);
                            }
                        }
                    }
                });
        stepsTable.setSortOrder(1, SortOrder.ASCENDING);

        JScrollPane allSteps = new JScrollPane(stepsTable);
        stepsTabbedPane.addTab(
                Constant.messages.getString("authhelper.authdiags.panel.tab.steps.all"), allSteps);
        steps.forEach(
                step ->
                        stepsPanels.computeIfAbsent(
                                step.getLabel(),
                                k -> {
                                    JPanel panel = new StepPanel(k, step);
                                    stepsTabbedPane.addTab(k, panel);
                                    return panel;
                                }));
        stepsTabbedPane.setSelectedComponent(allSteps);

        mainTabbedPane.addTab(
                Constant.messages.getString("authhelper.authdiags.panel.tab.steps"),
                stepsTabbedPane);
    }

    private static JTabbedPane createLeftTabbedPane() {
        String tabAlignmentProperty = "TabbedPane.tabAlignment";
        Object oldValue = UIManager.put(tabAlignmentProperty, "leading");
        JTabbedPane tabbedPane =
                new JTabbedPane(SwingConstants.LEFT, JTabbedPane.SCROLL_TAB_LAYOUT);
        UIManager.put(tabAlignmentProperty, oldValue);
        return tabbedPane;
    }

    private void addScreenshotsTab(
            TabbedPanel2 mainTabbedPane, DiagnosticUi diagnostic, List<StepUi> steps) {
        if (steps.stream().noneMatch(StepUi::hasScreenshot)) {
            return;
        }

        JPanel panel = new JPanel(new BorderLayout(5, 5));

        JToolBar toolBar = new JToolBar();
        panel.add(BorderLayout.PAGE_START, toolBar);

        JButton exportAllButton =
                createButton(
                        "authhelper.authdiags.panel.button.exportallscreenshots",
                        "/resource/icon/16/096.png");
        exportAllButton.addActionListener(
                e -> {
                    JFileChooser chooser = new JFileChooser(currentScreenshotDirectory);
                    chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                    if (chooser.showOpenDialog(DiagnosticPanel.this)
                            == JFileChooser.APPROVE_OPTION) {
                        File file = chooser.getSelectedFile();
                        if (file == null) {
                            return;
                        }

                        currentScreenshotDirectory = file;

                        Path parent = file.toPath();

                        for (StepUi step : steps) {
                            exportScreenshot(
                                    parent.resolve(getScreenshotFileName(diagnostic, step)), step);
                        }
                    }
                });
        toolBar.add(exportAllButton);

        JTabbedPane tabbedPane = createLeftTabbedPane();

        for (StepUi step : steps) {
            if (!step.hasScreenshot()) {
                continue;
            }

            JPanel screen = new JPanel(new BorderLayout());
            JButton exportButton =
                    createButton(
                            "authhelper.authdiags.panel.button.exportscreenshot",
                            "/resource/icon/16/096.png");
            exportButton.addActionListener(
                    e -> {
                        WritableFileChooser chooser =
                                new WritableFileChooser(currentScreenshotDirectory);
                        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                        chooser.setFileFilter(
                                new FileNameExtensionFilter(
                                        Constant.messages.getString(
                                                "authhelper.authdiags.panel.exportscreenshot.filter"),
                                        "png"));
                        chooser.setSelectedFile(new File(getScreenshotFileName(diagnostic, step)));
                        if (chooser.showOpenDialog(DiagnosticPanel.this)
                                == JFileChooser.APPROVE_OPTION) {
                            File file = chooser.getSelectedFile();
                            if (file == null) {
                                return;
                            }

                            currentScreenshotDirectory = file.getParentFile();

                            exportScreenshot(file.toPath(), step);
                        }
                    });

            JToolBar screenToolBar = new JToolBar();
            screenToolBar.add(exportButton);
            screen.add(BorderLayout.PAGE_START, screenToolBar);

            JLabel screenshotLabel = new JLabel();
            screenshotLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
            screenshotLabel.setVerticalAlignment(SwingConstants.TOP);
            screenshotLabel.setIcon(new ImageIcon(step.getScreenshotData()));
            screen.add(new JScrollPane(screenshotLabel));

            tabbedPane.addTab(step.getLabel(), screen);
        }

        panel.add(tabbedPane);

        mainTabbedPane.addTab(
                Constant.messages.getString("authhelper.authdiags.panel.tab.screenshots"), panel);
    }

    private static void exportScreenshot(Path path, StepUi step) {
        try {
            Files.write(path, step.getScreenshotData());
        } catch (IOException ex) {
            LOGGER.warn("An error occurred while writing the screenshot:", ex);
        }
    }

    private static String getScreenshotFileName(DiagnosticUi diagnostic, StepUi step) {
        return Constant.messages.getString(
                        "authhelper.authdiags.panel.filename.screenshot",
                        diagnostic.getId(),
                        step.getNumber())
                + ".png";
    }

    private static void addScriptTab(TabbedPanel2 mainTabbedPane, DiagnosticUi diagnostic) {
        String script = diagnostic.getScript();
        if (script == null) {
            return;
        }

        JPanel scriptPanel = new JPanel(new BorderLayout(5, 5));

        JToolBar toolBar = new JToolBar();
        scriptPanel.add(BorderLayout.PAGE_START, toolBar);

        RSyntaxTextArea scriptTextArea = new RSyntaxTextArea();
        scriptTextArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
        scriptTextArea.setHighlightCurrentLine(false);
        setText(scriptTextArea, script);
        scriptPanel.add(new RTextScrollPane(scriptTextArea, true));

        ExtensionZest extensionZest =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionZest.class);
        if (extensionZest != null) {
            JButton createScriptButton =
                    createButton(
                            "authhelper.authdiags.panel.button.createscript",
                            "/resource/icon/16/script-auth.png");
            createScriptButton.addActionListener(
                    e -> {
                        String scriptName =
                                Constant.messages.getString(
                                        "authhelper.authdiags.panel.label.scriptName",
                                        diagnostic.getId());
                        ExtensionScript extensionScript =
                                Control.getSingleton()
                                        .getExtensionLoader()
                                        .getExtension(ExtensionScript.class);
                        ScriptWrapper sw = extensionScript.getScript(scriptName);
                        if (sw != null) {
                            extensionScript.removeScript(sw);
                        }
                        sw = new ScriptWrapper();
                        sw.setName(scriptName);
                        sw.setContents(scriptTextArea.getText());
                        sw.setEngineName("Mozilla Zest");
                        sw.setType(extensionScript.getScriptType("authentication"));
                        extensionZest.add(new ZestScriptWrapper(sw), false);
                    });
            toolBar.add(createScriptButton);
        }

        JButton resetContentButton =
                createButton(
                        "authhelper.authdiags.panel.button.resetcontent",
                        "/resource/icon/16/126.png");
        resetContentButton.addActionListener(e -> setText(scriptTextArea, script));
        toolBar.add(resetContentButton);

        mainTabbedPane.addTab(
                Constant.messages.getString("authhelper.authdiags.panel.tab.script"), scriptPanel);
    }

    private static JButton createButton(String labelKey, String iconPath) {
        return new JButton(
                Constant.messages.getString(labelKey),
                DisplayUtils.getScaledIcon(DiagnosticPanel.class.getResource(iconPath)));
    }

    private static void setText(RSyntaxTextArea textArea, String script) {
        textArea.setText(script);
        textArea.setCaretPosition(0);
        textArea.discardAllEdits();
    }

    @SuppressWarnings("try")
    private static List<StepUi> readSteps(DiagnosticUi diagnostic) {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return List.of();
        }

        PersistenceManager pm = pmf.getPersistenceManager();
        try (Query<DiagnosticStep> query = pm.newQuery(DiagnosticStep.class)) {
            query.setFilter("this.diagnostic.id == :id");
            List<DiagnosticStep> stepsDb = query.setParameters(diagnostic.getId()).executeList();
            List<StepUi> stepsUi = new ArrayList<>();
            for (int i = 0; i < stepsDb.size(); i++) {
                stepsUi.add(new StepUi(i + 1, stepsDb.get(i)));
            }
            return stepsUi;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while reading diagnostics", e);
        } catch (Exception e) {
            LOGGER.error("An error occurred while getting the diagnostics:", e);
        } finally {
            pm.close();
        }
        return List.of();
    }
}
