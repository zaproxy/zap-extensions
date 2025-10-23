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

import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import javax.jdo.Transaction;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import javax.swing.SortOrder;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXErrorPane;
import org.jdesktop.swingx.error.ErrorInfo;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.authhelper.AuthhelperParam;
import org.zaproxy.addon.authhelper.ExtensionAuthhelper;
import org.zaproxy.addon.authhelper.internal.db.Diagnostic;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticBrowserStorageItem;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticMessage;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticScreenshot;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticStep;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticWebElement;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticWebElement.SelectorType;
import org.zaproxy.addon.authhelper.internal.db.TableJdo;
import org.zaproxy.addon.commonlib.ui.ReadableFileChooser;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.view.TabbedPanel2;
import org.zaproxy.zap.view.ZapTable;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestScript;

@SuppressWarnings("serial")
public class AllDiagnosticsPanel extends AbstractPanel {

    private static final Logger LOGGER = LogManager.getLogger(AllDiagnosticsPanel.class);

    private static final Clipboard CLIPBOARD = Toolkit.getDefaultToolkit().getSystemClipboard();

    private static final JsonMapper JSON_MAPPER =
            JsonMapper.builder()
                    .enable(JsonReadFeature.ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER)
                    .build();

    private static final long serialVersionUID = 1L;

    private final AuthhelperParam options;
    private final TabbedPanel2 tabbedPane;

    private final Map<String, AbstractPanel> diagnosticPanels;

    private final ZapTable table;
    private final AllDiagnosticsTableModel model;

    public AllDiagnosticsPanel(AuthhelperParam options, TabbedPanel2 tabbedPane) {
        this.options = options;
        this.tabbedPane = tabbedPane;

        setName(Constant.messages.getString("authhelper.authdiags.panel.all.title"));
        setHideable(false);
        setTabIndex(0);
        setLayout(new BorderLayout());

        JToolBar toolBar = new JToolBar();
        add(toolBar, BorderLayout.PAGE_START);

        diagnosticPanels = new HashMap<>();

        model = new AllDiagnosticsTableModel();
        table = new ZapTable(model);
        table.addMouseListener(
                new MouseAdapter() {

                    @Override
                    public void mousePressed(MouseEvent e) {
                        if (e.getClickCount() >= 2) {
                            int row = table.rowAtPoint(e.getPoint());
                            if (row >= 0) {
                                showDiagnostic(table.convertRowIndexToModel(row));
                            }
                        }
                    }
                });

        table.setSortOrder(1, SortOrder.ASCENDING);
        add(new JScrollPane(table), BorderLayout.CENTER);

        JButton viewButton =
                createButton("authhelper.authdiags.panel.view", "/resource/icon/16/049.png");
        viewButton.setEnabled(false);
        viewButton.addActionListener(e -> showDiagnostic(getSelectedRow()));
        toolBar.add(viewButton);

        JButton removeButton =
                createButton("authhelper.authdiags.panel.remove", "/resource/icon/fugue/broom.png");
        removeButton.setEnabled(false);
        removeButton.addActionListener(
                e -> {
                    int result =
                            View.getSingleton()
                                    .showConfirmDialog(
                                            AllDiagnosticsPanel.this,
                                            Constant.messages.getString(
                                                    "authhelper.authdiags.panel.remove.warn"));
                    if (result == JOptionPane.OK_OPTION) {
                        PersistenceManagerFactory pmf = TableJdo.getPmf();
                        if (pmf == null) {
                            return;
                        }

                        int selectedRow = getSelectedRow();
                        DiagnosticUi diags = model.getDiagnostic(selectedRow);
                        String tabName = getTabName(diags);

                        PersistenceManager pm = pmf.getPersistenceManager();
                        Transaction tx = pm.currentTransaction();
                        try {
                            tx.begin();

                            pm.deletePersistent(pm.getObjectById(Diagnostic.class, diags.getId()));

                            tx.commit();
                            model.remove(selectedRow);

                            diagnosticPanels.computeIfPresent(
                                    tabName,
                                    (k, v) -> {
                                        tabbedPane.removeTab(v);
                                        return null;
                                    });
                        } catch (Exception ex) {
                            LOGGER.warn("An error occurred while deleting the diagnostic:", ex);
                        } finally {
                            if (tx.isActive()) {
                                tx.rollback();
                            }
                            pm.close();
                        }
                    }
                });
        toolBar.add(removeButton);
        toolBar.addSeparator();

        JButton importFileButton =
                createButton("authhelper.authdiags.panel.import.file", "/resource/icon/16/047.png");
        importFileButton.addActionListener(
                e -> {
                    JFileChooser chooser =
                            new ReadableFileChooser(new File(options.getAuthReportDir()));
                    chooser.setFileFilter(
                            new FileNameExtensionFilter(
                                    Constant.messages.getString(
                                            "authhelper.authdiags.panel.import.filter"),
                                    "json"));

                    if (chooser.showOpenDialog(AllDiagnosticsPanel.this)
                            == JFileChooser.APPROVE_OPTION) {
                        File file = chooser.getSelectedFile();
                        if (file == null) {
                            return;
                        }

                        File parent = file.getParentFile();
                        options.setAuthReportDir(parent != null ? parent.getAbsolutePath() : null);

                        new Thread(() -> importFileReport(file), "ZAP-DiagsFileImport").start();
                    }
                });
        toolBar.add(importFileButton);

        JButton importClipboardButton =
                createButton(
                        "authhelper.authdiags.panel.import.clipboard",
                        ExtensionAuthhelper.RESOURCES_DIR + "images/clipboard-sign.png");
        importClipboardButton.addActionListener(
                e ->
                        new Thread(
                                        AllDiagnosticsPanel.this::importClipboardReport,
                                        "ZAP-DiagsClipboardImport")
                                .start());
        toolBar.add(importClipboardButton);
        toolBar.addSeparator();

        JButton refreshButton =
                createButton("authhelper.authdiags.panel.refresh", "/resource/icon/16/126.png");
        refreshButton.addActionListener(e -> refresh());
        toolBar.add(refreshButton);

        table.getSelectionModel()
                .addListSelectionListener(
                        e -> {
                            boolean selection = table.getSelectedRowCount() == 1;
                            viewButton.setEnabled(selection);
                            removeButton.setEnabled(selection);
                        });

        refresh();

        tabbedPane.addTab(this);
    }

    private static JButton createButton(String labelKey, String iconPath) {
        return new JButton(
                Constant.messages.getString(labelKey),
                DisplayUtils.getScaledIcon(AllDiagnosticsPanel.class.getResource(iconPath)));
    }

    public void refresh() {
        clear();

        model.setEntries(readDiags());
        table.packAll();
    }

    public void clear() {
        diagnosticPanels.values().forEach(tabbedPane::removeTab);
        diagnosticPanels.clear();

        model.clear();
    }

    @SuppressWarnings("try")
    private List<DiagnosticUi> readDiags() {
        PersistenceManagerFactory pmf = TableJdo.getPmf();
        if (pmf == null) {
            return List.of();
        }

        PersistenceManager pm = pmf.getPersistenceManager();
        try (Query<Diagnostic> query = pm.newQuery(Diagnostic.class)) {
            return query.executeList().stream().map(DiagnosticUi::new).toList();
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

    private void showDiagnostic(int row) {
        DiagnosticUi diagnostic = model.getDiagnostic(row);

        String name = getTabName(diagnostic);
        AbstractPanel diagnosticPanel =
                diagnosticPanels.computeIfAbsent(
                        name,
                        k -> {
                            AbstractPanel panel = new DiagnosticPanel(options, k, diagnostic);
                            tabbedPane.addTab(panel);
                            return panel;
                        });

        diagnosticPanel.setTabFocus();
    }

    private static String getTabName(DiagnosticUi diagnostic) {
        return Constant.messages.getString(
                "authhelper.authdiags.panel.diagnostic.title", diagnostic.getId());
    }

    private int getSelectedRow() {
        return table.convertColumnIndexToModel(table.getSelectedRow());
    }

    private void importFileReport(File file) {
        try {
            importDiagnosticData(
                    JSON_MAPPER.readValue(file, new TypeReference<Map<String, Object>>() {}));
        } catch (Exception e) {
            LOGGER.warn("An error occurred while parsing the authentication report:", e);
            showErrorDialog("authhelper.authdiags.manager.import.error.parse", e);
        }
    }

    private static void showErrorDialog(String errorKey, Exception e) {
        ErrorInfo errorInfo =
                new ErrorInfo(
                        Constant.messages.getString(
                                "authhelper.authdiags.manager.import.error.title"),
                        Constant.messages.getString(errorKey),
                        null,
                        null,
                        e,
                        Level.WARNING,
                        null);
        JXErrorPane errorPane = new JXErrorPane();
        errorPane.setErrorInfo(errorInfo);
        JXErrorPane.showDialog(null, errorPane);
    }

    private void importClipboardReport() {
        String data = null;
        try {
            Transferable transferable = CLIPBOARD.getContents(null);
            data = (String) transferable.getTransferData(DataFlavor.stringFlavor);
        } catch (Exception e) {
            LOGGER.warn("An error occurred while processing the clipboard:", e);
            showErrorDialog("authhelper.authdiags.manager.import.error.clipboard", e);
            return;
        }

        try {
            importDiagnosticData(
                    JSON_MAPPER.readValue(data, new TypeReference<Map<String, Object>>() {}));
        } catch (Exception e) {
            LOGGER.warn("An error occurred while parsing the authentication report:", e);
            showErrorDialog("authhelper.authdiags.manager.import.error.parse", e);
        }
    }

    @SuppressWarnings("unchecked")
    private void importDiagnosticData(Map<String, Object> report) {
        try {
            List<Map<String, Object>> diagnostics =
                    (List<Map<String, Object>>) report.get("diagnostics");
            if (diagnostics == null || diagnostics.isEmpty()) {
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        "authhelper.authdiags.manager.import.nodiagnostics"));
                return;
            }

            for (Map<String, Object> diagnosticData : diagnostics) {
                Diagnostic diagnostic = new Diagnostic();

                diagnostic.setCreateTimestamp(
                        Instant.parse((String) diagnosticData.get("created")));
                diagnostic.setAuthenticationMethod(
                        (String) diagnosticData.get("authenticationMethod"));
                diagnostic.setContext((String) diagnosticData.get("context"));
                diagnostic.setUser((String) diagnosticData.get("user"));
                diagnostic.setScript(updateScript((String) diagnosticData.get("script")));
                diagnostic.setAfPlan((String) diagnosticData.get("afPlan"));

                List<Map<String, Object>> stepsData =
                        (List<Map<String, Object>>) diagnosticData.get("steps");
                for (Map<String, Object> stepData : stepsData) {
                    DiagnosticStep diagnosticStep = new DiagnosticStep();
                    diagnostic.getSteps().add(diagnosticStep);

                    diagnosticStep.setCreateTimestamp(
                            Instant.parse((String) stepData.get("created")));
                    diagnosticStep.setDiagnostic(diagnostic);
                    diagnosticStep.setUrl((String) stepData.get("url"));
                    diagnosticStep.setDescription((String) stepData.get("description"));

                    diagnosticStep.setWebElement(
                            readWebElement((Map<String, Object>) stepData.get("webElement")));
                    readScreenshot(diagnosticStep, (String) stepData.get("screenshot"));
                    readMessages(
                            diagnosticStep, (List<Map<String, Object>>) stepData.get("messages"));
                    readWebElements(
                            diagnosticStep,
                            (List<Map<String, Object>>) stepData.get("webElements"));
                    readBrowserStorageItems(
                            diagnosticStep,
                            (List<Map<String, Object>>) stepData.get("localStorage"),
                            (List<Map<String, Object>>) stepData.get("sessionStorage"));
                }

                persistDiagnostic(diagnostic);
            }

        } catch (Exception e) {
            LOGGER.warn(e.getMessage(), e);
            showErrorDialog("authhelper.authdiags.manager.import.error", e);
        }
    }

    private static String updateScript(String script) {
        if (script == null || script.isBlank()) {
            return script;
        }

        ExtensionZest extensionZest =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionZest.class);
        if (extensionZest != null) {
            try {
                ZestScript zs = (ZestScript) extensionZest.convertStringToElement(script);
                zs.getStatements().stream()
                        .filter(ZestClientLaunch.class::isInstance)
                        .map(ZestClientLaunch.class::cast)
                        .forEach(e -> e.setHeadless(false));
                return extensionZest.convertElementToString(zs);
            } catch (Exception e) {
                LOGGER.warn("An error occurred while updating the script:", e);
            }
        }
        return script;
    }

    private void readScreenshot(DiagnosticStep diagnosticStep, String data) {
        if (data == null) {
            return;
        }
        DiagnosticScreenshot diagnosticScreenshot = new DiagnosticScreenshot();
        diagnosticScreenshot.setStep(diagnosticStep);
        diagnosticScreenshot.setData(data);
        diagnosticStep.setScreenshot(diagnosticScreenshot);
    }

    private DiagnosticWebElement readWebElement(Map<String, Object> webElementData) {
        if (webElementData == null) {
            return null;
        }

        DiagnosticWebElement diagnosticWebElement = new DiagnosticWebElement();

        diagnosticWebElement.setFormIndex((Integer) webElementData.get("formIndex"));
        diagnosticWebElement.setTagName((String) webElementData.get("tagName"));
        diagnosticWebElement.setAttributeType((String) webElementData.get("attributeType"));
        diagnosticWebElement.setAttributeId((String) webElementData.get("attributeId"));
        diagnosticWebElement.setAttributeName((String) webElementData.get("attributeName"));
        diagnosticWebElement.setAttributeValue((String) webElementData.get("attributeValue"));
        diagnosticWebElement.setText((String) webElementData.get("text"));
        diagnosticWebElement.setDisplayed((Boolean) webElementData.get("displayed"));
        diagnosticWebElement.setEnabled((Boolean) webElementData.get("enabled"));

        @SuppressWarnings("unchecked")
        Map<String, Object> selectorData = (Map<String, Object>) webElementData.get("selector");
        if (selectorData != null) {
            diagnosticWebElement.setSelectorType(
                    SelectorType.valueOf((String) selectorData.get("type")));
            diagnosticWebElement.setSelectorValue((String) selectorData.get("value"));
        }
        return diagnosticWebElement;
    }

    private void readWebElements(
            DiagnosticStep diagnosticStep, List<Map<String, Object>> webElementsData) {
        if (webElementsData == null) {
            return;
        }

        for (Map<String, Object> webElementData : webElementsData) {
            diagnosticStep.getWebElements().add(readWebElement(webElementData));
        }
    }

    private void readBrowserStorageItems(
            DiagnosticStep diagnosticStep,
            List<Map<String, Object>> localStorageData,
            List<Map<String, Object>> sessionStorageData) {
        if (localStorageData != null) {
            localStorageData.stream()
                    .map(
                            e ->
                                    readBrowserStorageItem(
                                            e,
                                            diagnosticStep,
                                            DiagnosticBrowserStorageItem.Type.LOCAL))
                    .forEach(diagnosticStep.getBrowserStorageItems()::add);
        }

        if (sessionStorageData != null) {
            sessionStorageData.stream()
                    .map(
                            e ->
                                    readBrowserStorageItem(
                                            e,
                                            diagnosticStep,
                                            DiagnosticBrowserStorageItem.Type.SESSION))
                    .forEach(diagnosticStep.getBrowserStorageItems()::add);
        }
    }

    private DiagnosticBrowserStorageItem readBrowserStorageItem(
            Map<String, Object> data,
            DiagnosticStep diagnosticStep,
            DiagnosticBrowserStorageItem.Type type) {
        DiagnosticBrowserStorageItem diagnosticBrowserStorageItem =
                new DiagnosticBrowserStorageItem();
        diagnosticBrowserStorageItem.setCreateTimestamp(
                Instant.parse((String) data.get("created")));
        diagnosticBrowserStorageItem.setType(type);
        diagnosticBrowserStorageItem.setKey((String) data.get("key"));
        diagnosticBrowserStorageItem.setValue((String) data.get("value"));
        diagnosticBrowserStorageItem.setStep(diagnosticStep);
        return diagnosticBrowserStorageItem;
    }

    private void readMessages(
            DiagnosticStep diagnosticStep, List<Map<String, Object>> messagesData) {
        if (messagesData == null) {
            return;
        }

        ExtensionHistory extensionHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);

        for (Map<String, Object> messageData : messagesData) {
            try {
                HttpMessage message = new HttpMessage();
                message.setRequestHeader((String) messageData.get("requestHeader"));
                message.setRequestBody((String) messageData.get("requestBody"));

                message.setResponseHeader((String) messageData.get("responseHeader"));
                message.setResponseBody((String) messageData.get("responseBody"));

                Instant created = Instant.parse((String) messageData.get("created"));
                message.setTimeSentMillis(created.toEpochMilli());
                Integer rtt = (Integer) messageData.get("rtt");
                if (rtt != null) {
                    message.setTimeElapsedMillis(rtt);
                }
                message.setResponseFromTargetHost(true);

                HistoryReference ref =
                        new HistoryReference(
                                Model.getSingleton().getSession(),
                                HistoryReference.TYPE_PROXIED,
                                message);

                Integer initiator = (Integer) messageData.get("initiator");
                ref.setTags(
                        List.of(
                                Constant.messages.getString(
                                        "authhelper.authdiags.message.tag.initiator", initiator)));

                if (extensionHistory != null) {
                    EventQueue.invokeLater(
                            () -> {
                                extensionHistory.addHistory(ref);
                                SessionStructure.addPath(extensionHistory.getModel(), ref, message);
                            });
                }

                DiagnosticMessage diagnosticMessage = new DiagnosticMessage();
                diagnosticMessage.setStep(diagnosticStep);
                diagnosticMessage.setCreateTimestamp(created);
                diagnosticMessage.setMessageId(ref.getHistoryId());
                diagnosticMessage.setInitiator(initiator);
                diagnosticStep.getMessages().add(diagnosticMessage);

            } catch (Exception e) {
                LOGGER.warn(e.getMessage(), e);
            }
        }
    }

    private void persistDiagnostic(Diagnostic diagnostic) {
        PersistenceManager pm = TableJdo.getPmf().getPersistenceManager();
        Transaction tx = pm.currentTransaction();
        try {
            tx.begin();
            pm.makePersistent(diagnostic);
            tx.commit();

            DiagnosticUi diagnosticUi = new DiagnosticUi(diagnostic);
            ThreadUtils.invokeLater(() -> model.addEntry(diagnosticUi));

        } catch (Exception e) {
            LOGGER.warn("Failed to persist diagnostic:", e);
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            pm.close();
        }
    }
}
