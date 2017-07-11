/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.fieldenumeration;

import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.Insets;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.AbstractFrame;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

public class EnumerationResult extends AbstractFrame {
    private static final long serialVersionUID = 1L;
    private static final String CSV_EXTENSION = ".csv";
    private static final Logger LOGGER = LogManager.getLogger(EnumerationResult.class);
    private JButton blacklist =
            new JButton(Constant.messages.getString("fieldenumeration.blacklist"));
    private JButton save = new JButton(Constant.messages.getString("fieldenumeration.export.csv"));
    private JTable jTable = new JTable();
    private JPanel result = new JPanel();
    private JLabel fieldSelected = new JLabel();
    private JLabel statusCode = new JLabel();
    private JTextArea blackChars = new JTextArea();
    private GridBagConstraints c = new GridBagConstraints();
    private Font font = new Font("Courier", Font.BOLD, 12);

    private JTable exportTable = jTable;
    private final JDialog dialog = new JDialog();

    public EnumerationResult() throws HeadlessException {
        super();
        this.setTitle(Constant.messages.getString("fieldenumeration.result"));
        this.setContentPane(getResult());

        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            this.setSize(400, 400);
        }

        pack();
    }

    private JPanel getResult() {
        result.setLayout(new GridBagLayout());
        c.fill = GridBagConstraints.BOTH;
        c.gridx = 0;
        c.gridy = 0;
        result.add(fieldSelected, c);
        c.gridx = 0;
        c.gridy = 2;
        result.add(statusCode, c);
        c.anchor = GridBagConstraints.NORTH;
        c.insets = new Insets(0, 0, 0, 10);
        c.weightx = 1;
        c.gridwidth = 2;
        c.gridx = 0;
        c.gridy = 4;
        result.add(blacklist, c);
        c.ipady = 110; // make this component tall
        c.anchor = GridBagConstraints.CENTER;
        c.weightx = 1;
        c.gridx = 0;
        c.gridy = 6;
        result.add(new JScrollPane(jTable), c);
        c.anchor = GridBagConstraints.NORTH;
        c.insets = new Insets(0, 0, 0, 10);
        c.weightx = 1;
        c.gridwidth = 2;
        c.gridx = 0;
        c.gridy = 7;
        c.ipadx = 10;
        c.ipady = 10;
        result.add(save, c);
        result.setVisible(true);

        save.addActionListener(
                e -> {
                    WritableFileChooser chooser =
                            new WritableFileChooser(
                                    Model.getSingleton().getOptionsParam().getUserDirectory()) {

                                private static final long serialVersionUID = 1L;

                                @Override
                                public void approveSelection() {
                                    File file = getSelectedFile();
                                    if (file != null) {
                                        String filePath = file.getAbsolutePath();
                                        if (!filePath.toLowerCase(Locale.ROOT)
                                                .endsWith(CSV_EXTENSION)) {
                                            setSelectedFile(new File(filePath + CSV_EXTENSION));
                                        }
                                    }
                                    super.approveSelection();
                                }
                            };

                    chooser.setSelectedFile(
                            new File(
                                    Constant.messages.getString("export.button.default.filename")));
                    if (chooser.showSaveDialog(View.getSingleton().getMainFrame())
                            == JFileChooser.APPROVE_OPTION) {
                        boolean success = true;
                        try (CSVPrinter pw =
                                new CSVPrinter(
                                        Files.newBufferedWriter(
                                                chooser.getSelectedFile().toPath(),
                                                StandardCharsets.UTF_8),
                                        CSVFormat.DEFAULT)) {
                            pw.printRecord(getColumnNames());
                            int rowCount = getTable().getRowCount();
                            for (int row = 0; row < rowCount; row++) {
                                pw.printRecord(getRowCells(row));
                            }
                        } catch (Exception ex) {
                            success = false;
                            JOptionPane.showMessageDialog(
                                    View.getSingleton().getMainFrame(),
                                    Constant.messages.getString("export.button.error")
                                            + "\n"
                                            + ex.getMessage());
                            LOGGER.error("Export Failed: " + ex.getMessage(), ex);
                        }
                        if (success) {
                            JOptionPane.showMessageDialog(
                                    View.getSingleton().getMainFrame(),
                                    Constant.messages.getString("export.button.success"));
                        }
                    }
                });
        pack();
        return result;
    }

    protected List<String> getColumnNames() {
        List<String> columnNamesList = new ArrayList<>();
        for (int col = 0; col < getTable().getColumnCount(); col++) {
            columnNamesList.add(
                    getTable().getColumnModel().getColumn(col).getHeaderValue().toString());
        }
        return columnNamesList;
    }

    protected List<Object> getRowCells(int row) {
        List<Object> cells = new ArrayList<>();
        for (int col = 0; col < getTable().getColumnCount(); col++) {
            Object value = getTable().getValueAt(row, col);
            cells.add(value == null ? "" : value.toString());
        }
        return cells;
    }

    protected JTable getTable() {
        return exportTable;
    }

    public void setTable(JTable table) {
        this.exportTable = table;
    }

    public void addFields(
            String field, String regex, DefaultTableModel model, final StringBuilder iChars) {
        fieldSelected.setText(
                Constant.messages.getString("fieldenumeration.field.selected") + field);
        fieldSelected.setFont(font);
        statusCode.setText(Constant.messages.getString("fieldenumeration.status.code") + regex);
        statusCode.setFont(font);
        jTable.setModel(model);

        JTextField tf = new JTextField();
        tf.setEditable(false);
        DefaultCellEditor editor = new DefaultCellEditor(tf);
        jTable.setDefaultEditor(EnumerationResult.class, editor);

        blacklist.addActionListener(
                e -> {
                    blackChars.append(iChars.toString());
                    JScrollPane sp = new JScrollPane(blackChars);
                    dialog.setModal(true);
                    dialog.setTitle(Constant.messages.getString("fieldenumeration.blacklist"));
                    dialog.setSize(new Dimension(400, 400));
                    dialog.add(sp);
                    dialog.setVisible(true);
                    // JOptionPane.showMessageDialog(EnumerationResult.this,
                    //		Constant.messages.getString("fieldenumeration.illegal") + "\n" +
                    // iChars.toString());
                });

        pack();
    }
}
