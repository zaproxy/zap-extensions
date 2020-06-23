/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.cmss;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JLayeredPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;
import org.apache.commons.codec.DecoderException;

public class CMSSFrame extends JFrame {

    /** */
    private static final long serialVersionUID = 1L;

    private JPanel contentPane;
    private JTextField textField;
    private JTextField textField_1;

    private FingerPrintingThread fpThread = null;
    private URL targetUrl = null;

    // we save in this list all checkBoses then use them to get web apps category names and then
    // category numbers
    private ArrayList<javax.swing.JCheckBox> checkBoxesList =
            new ArrayList<javax.swing.JCheckBox>();

    private WhatToFingerPrintFrame wtfpFrame = new WhatToFingerPrintFrame();

    private int POrAOption = 1;
    private JTextField txtHttp;

    /** Create the frame. */
    public CMSSFrame() {
        setTitle("Fingerprinting tools");
        setResizable(false);
        setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
        setBounds(100, 100, 756, 372);
        contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        contentPane.setLayout(new BorderLayout(0, 0));
        setContentPane(contentPane);

        JLayeredPane layeredPane = new JLayeredPane();
        contentPane.add(layeredPane, BorderLayout.CENTER);

        JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
        tabbedPane.setBounds(0, 0, 725, 323);
        layeredPane.add(tabbedPane);

        JLayeredPane layeredPane_1 = new JLayeredPane();
        tabbedPane.addTab("Fingerprint", null, layeredPane_1, null);

        JLabel label = new JLabel("App name:");
        label.setBounds(35, 188, 76, 14);
        layeredPane_1.add(label);

        JLabel label_1 = new JLabel("Version:");
        label_1.setBounds(35, 230, 76, 14);
        layeredPane_1.add(label_1);

        textField = new JTextField();
        textField.setColumns(10);
        textField.setBounds(121, 188, 109, 29);
        layeredPane_1.add(textField);

        textField_1 = new JTextField();
        textField_1.setColumns(10);
        textField_1.setBounds(121, 223, 109, 29);
        layeredPane_1.add(textField_1);

        JSeparator separator = new JSeparator();
        separator.setBounds(35, 72, 665, 2);
        layeredPane_1.add(separator);

        JSeparator separator_1 = new JSeparator();
        separator_1.setBounds(196, 11, 1, 201);
        layeredPane_1.add(separator_1);

        JSeparator separator_2 = new JSeparator();
        separator_2.setOrientation(SwingConstants.VERTICAL);
        separator_2.setBounds(260, 81, 1, 201);
        layeredPane_1.add(separator_2);

        final JCheckBox chckbxGetVersion = new JCheckBox("Get version");
        chckbxGetVersion.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {

                        if (textField_1.isEnabled() && !chckbxGetVersion.isSelected())
                            textField_1.setEnabled(false);
                        if (!textField_1.isEnabled() && chckbxGetVersion.isSelected())
                            textField_1.setEnabled(true);
                    }
                });
        chckbxGetVersion.setBounds(35, 81, 195, 23);
        layeredPane_1.add(chckbxGetVersion);

        final JCheckBox chckbxPassiveFingerprinting = new JCheckBox("Passive");
        chckbxPassiveFingerprinting.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {}
                });
        chckbxPassiveFingerprinting.setBounds(35, 107, 195, 23);
        chckbxPassiveFingerprinting.setSelected(true); //
        layeredPane_1.add(chckbxPassiveFingerprinting);

        final JCheckBox chckbxAgressive = new JCheckBox("Agressive");
        chckbxAgressive.setBounds(35, 133, 195, 23);
        layeredPane_1.add(chckbxAgressive);

        JLabel lblWhatToFingerprint = new JLabel("What to fingerprint ?");
        lblWhatToFingerprint.setBounds(287, 81, 109, 14);
        layeredPane_1.add(lblWhatToFingerprint);

        JCheckBox chckbxCms = new JCheckBox("cms");
        chckbxCms.setBounds(280, 102, 134, 23);
        layeredPane_1.add(chckbxCms);

        JCheckBox chckbxMessageboards = new JCheckBox("message-boards");
        chckbxMessageboards.setBounds(280, 128, 134, 23);
        layeredPane_1.add(chckbxMessageboards);

        JCheckBox chckbxJavascriptframeworks = new JCheckBox("javascript-frameworks");
        chckbxJavascriptframeworks.setBounds(281, 154, 133, 23);
        layeredPane_1.add(chckbxJavascriptframeworks);

        JCheckBox chckbxWebframeworks = new JCheckBox("web-frameworks");
        chckbxWebframeworks.setBounds(281, 178, 133, 23);
        layeredPane_1.add(chckbxWebframeworks);

        JCheckBox chckbxWebservers = new JCheckBox("web-servers");
        chckbxWebservers.setBounds(281, 204, 133, 23);
        layeredPane_1.add(chckbxWebservers);

        JSeparator separator_4 = new JSeparator();
        separator_4.setOrientation(SwingConstants.VERTICAL);
        separator_4.setBounds(435, 81, 1, 201);
        layeredPane_1.add(separator_4);

        JCheckBox chckbxDatabases = new JCheckBox("databases");
        chckbxDatabases.setBounds(281, 228, 133, 23);
        layeredPane_1.add(chckbxDatabases);

        JButton btnMore = new JButton("More");
        btnMore.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        wtfpFrame = new WhatToFingerPrintFrame();
                        wtfpFrame.setLocationRelativeTo(null);
                        wtfpFrame.setVisible(true);
                    }
                });
        btnMore.setBounds(291, 261, 123, 23);
        layeredPane_1.add(btnMore);

        JLabel lblFingerprintingTimeAnd = new JLabel("Fingerprinting time and occuracy settings:");
        lblFingerprintingTimeAnd.setBounds(490, 81, 210, 14);
        layeredPane_1.add(lblFingerprintingTimeAnd);

        JButton btnFingerprint = new JButton("Fingerprint");
        btnFingerprint.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (!chckbxPassiveFingerprinting.isSelected()
                                && !chckbxAgressive.isSelected())
                            chckbxPassiveFingerprinting.setSelected(true);
                        if (chckbxPassiveFingerprinting.isSelected()
                                && !chckbxAgressive.isSelected()) POrAOption = 1;
                        else if (!chckbxPassiveFingerprinting.isSelected()
                                && chckbxAgressive.isSelected()) POrAOption = 2;
                        else if (chckbxPassiveFingerprinting.isSelected()
                                && chckbxAgressive.isSelected()) POrAOption = 3;

                        try {
                            targetUrl = new URL(txtHttp.getText());
                        } catch (MalformedURLException e2) {
                            // TODO Auto-generated catch block
                            e2.printStackTrace();
                        }

                        System.out.println("POrAOption : " + POrAOption);

                        // we concatenate the two ArrayLists
                        ArrayList<String> wtfpList = getWhatToFingerprint();
                        for (String wtfp : wtfpFrame.getWhatToFingerprint()) {
                            wtfpList.add(wtfp);
                        }
                        // we call FastFingerprinter.filterResults on the global whatToFingerPrint
                        // List

                        fpThread = new FingerPrintingThread(targetUrl, wtfpList, POrAOption);
                        fpThread.start();
                        while (fpThread.isAlive()) {
                            // waiting;

                        }
                        ArrayList<String> resultList = fpThread.getFingerPrintingResult();
                        for (String app : resultList) {
                            textField.setText(textField.getText() + app + " , ");
                        }

                        if (chckbxGetVersion.isSelected()) {
                            System.out.println("wiw");
                            ArrayList<String> versions = new ArrayList<String>();

                            if (resultList.contains("wordpress")) {
                                textField_1.setText(textField_1.getText() + "wordpress :");
                                for (String version :
                                        FastFingerprinter.WordpressFastFingerprint(targetUrl)) {
                                    textField_1.setText(textField_1.getText() + version + " ; ");
                                }
                            }

                            if (resultList.contains("joomla")) {
                                textField_1.setText(textField_1.getText() + "joomla :");
                                for (String version :
                                        FastFingerprinter.JoomlaFastFingerprint(targetUrl)) {
                                    textField_1.setText(textField_1.getText() + version + " ; ");
                                }
                            }

                            // blindelephant
                            for (String app : resultList) {
                                System.out.println("---->" + app);
                                try {
                                    versions = WebAppGuesser.fingerPrintFile(app);
                                    textField_1.setText(textField_1.getText() + app + " : ");
                                    for (String version : versions) {
                                        textField_1.setText(
                                                textField_1.getText() + version + " ; ");
                                    }
                                } catch (NoSuchAlgorithmException
                                        | IOException
                                        | DecoderException e1) {
                                    e1.printStackTrace();
                                }
                            }
                        }
                    }
                });

        btnFingerprint.setBounds(35, 154, 195, 23);
        layeredPane_1.add(btnFingerprint);

        JButton btnDetailedView = new JButton("Detailed view ");
        btnDetailedView.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {}
                });
        btnDetailedView.setBounds(35, 259, 195, 23);
        layeredPane_1.add(btnDetailedView);
        this.checkBoxesList.add(chckbxCms);
        this.checkBoxesList.add(chckbxJavascriptframeworks);
        this.checkBoxesList.add(chckbxWebframeworks);
        this.checkBoxesList.add(chckbxWebservers);
        this.checkBoxesList.add(chckbxDatabases);
        this.checkBoxesList.add(chckbxMessageboards);

        txtHttp = new JTextField();
        txtHttp.setText("http://");
        txtHttp.setBounds(128, 22, 568, 29);
        layeredPane_1.add(txtHttp);
        txtHttp.setColumns(10);

        JLabel lblTarget = new JLabel("Target : ");
        lblTarget.setBounds(51, 29, 46, 14);
        layeredPane_1.add(lblTarget);

        JLayeredPane layeredPane_2 = new JLayeredPane();
        tabbedPane.addTab("Details", null, layeredPane_2, null);

        JTabbedPane tabbedPane_1 = new JTabbedPane(JTabbedPane.TOP);
        tabbedPane_1.setBounds(0, 0, 720, 223);
        layeredPane_2.add(tabbedPane_1);

        JLayeredPane layeredPane_4 = new JLayeredPane();
        tabbedPane_1.addTab("Detailed result", null, layeredPane_4, null);

        JLayeredPane layeredPane_3 = new JLayeredPane();
        tabbedPane_1.addTab("Passive fingerprint", null, layeredPane_3, null);

        JTabbedPane tabbedPane_2 = new JTabbedPane(JTabbedPane.TOP);
        tabbedPane_1.addTab("Agressive fingerprint", null, tabbedPane_2, null);
    }

    private ArrayList<String> getWhatToFingerprint() {
        ArrayList<String> WhatToFingerprint = new ArrayList<String>();
        for (JCheckBox checkBox : checkBoxesList) {
            if (checkBox.isSelected()) {
                System.out.println("check boxe : " + checkBox.getText());
                WhatToFingerprint.add(checkBox.getText());
            }
        }
        return WhatToFingerprint;
    }
}
