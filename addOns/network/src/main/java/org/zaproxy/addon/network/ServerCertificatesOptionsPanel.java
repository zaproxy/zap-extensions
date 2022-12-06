/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.network;

import java.awt.Desktop;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Locale;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileFilter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.network.internal.cert.CertConfig;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapXmlConfiguration;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

@SuppressWarnings("serial")
class ServerCertificatesOptionsPanel extends AbstractParamPanel {

    private static final Logger LOGGER = LogManager.getLogger(ServerCertificatesOptionsPanel.class);

    private static final String OWASP_ZAP_ROOT_CA_NAME = "owasp_zap_root_ca";
    private static final String OWASP_ZAP_ROOT_CA_FILE_EXT = ".cer";
    private static final String OWASP_ZAP_ROOT_CA_FILENAME =
            OWASP_ZAP_ROOT_CA_NAME + OWASP_ZAP_ROOT_CA_FILE_EXT;

    private static final String CONFIGURATION_FILENAME = Constant.FILE_CONFIG_NAME;

    private static final long serialVersionUID = 1L;

    private final RootCaCertificatePanel rootCaCertificatePanel;
    private final IssuedCertificatesPanel issuedCertificatesPanel;

    public ServerCertificatesOptionsPanel(ExtensionNetwork extensionNetwork) {
        rootCaCertificatePanel = new RootCaCertificatePanel(extensionNetwork);
        issuedCertificatesPanel = new IssuedCertificatesPanel();

        setName(Constant.messages.getString("network.ui.options.servercertificates.name"));

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.add(
                Constant.messages.getString("network.ui.options.servercertificates.tab.rootcacert"),
                rootCaCertificatePanel.getPanel());
        tabbedPane.add(
                Constant.messages.getString(
                        "network.ui.options.servercertificates.tab.issuedcerts"),
                issuedCertificatesPanel.getPanel());

        GroupLayout mainLayout = new GroupLayout(this);
        setLayout(mainLayout);
        mainLayout.setAutoCreateGaps(true);
        mainLayout.setAutoCreateContainerGaps(true);

        mainLayout.setHorizontalGroup(mainLayout.createParallelGroup().addComponent(tabbedPane));
        mainLayout.setVerticalGroup(mainLayout.createSequentialGroup().addComponent(tabbedPane));
    }

    @Override
    public void initParam(Object mainOptions) {
        ServerCertificatesOptions options = getServerCertificatesOptions(mainOptions);

        rootCaCertificatePanel.init(options);
        issuedCertificatesPanel.init(options);
    }

    private static ServerCertificatesOptions getServerCertificatesOptions(Object mainOptions) {
        return ((OptionsParam) mainOptions).getParamSet(ServerCertificatesOptions.class);
    }

    @Override
    public void saveParam(Object mainOptions) throws Exception {
        ServerCertificatesOptions options = getServerCertificatesOptions(mainOptions);

        rootCaCertificatePanel.save(options);
        issuedCertificatesPanel.save(options);
    }

    @Override
    public String getHelpIndex() {
        return "addon.network.options.servercertificates";
    }

    private static class RootCaCertificatePanel {

        private final ZapNumberSpinner numberSpinnerValidity;
        private final JButton buttonGenerate;
        private final JButton buttonImport;
        private final JButton buttonView;
        private final JButton buttonSave;
        private final JTextArea textAreaPem;

        private final ExtensionNetwork extensionNetwork;
        private final JPanel panel;
        private KeyStore currentRootCaCert;

        RootCaCertificatePanel(ExtensionNetwork extensionNetwork) {
            this.extensionNetwork = extensionNetwork;
            JLabel labelValidity =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.servercertificates.field.certvalidity"));
            numberSpinnerValidity =
                    new ZapNumberSpinner(
                            1,
                            ServerCertificatesOptions.DEFAULT_ROOT_CA_CERT_VALIDITY,
                            ServerCertificatesOptions.DEFAULT_ROOT_CA_CERT_VALIDITY * 10);

            buttonGenerate = createButton("generate", "041.png", e -> generateRootCaCert());
            buttonImport = createButton("import", "047.png", e -> importRootCaCert());
            buttonView = createButton("view", "049.png", e -> viewRootCaCert());
            buttonView.setEnabled(false);
            buttonSave = createButton("save", "096.png", e -> saveRootCaCert());
            buttonSave.setEnabled(false);

            JLabel labelPem =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.servercertificates.field.pem"));
            textAreaPem = new JTextArea();
            textAreaPem.setEditable(false);
            textAreaPem.setFont(FontUtils.getFont("Monospaced"));
            textAreaPem
                    .getDocument()
                    .addDocumentListener(
                            new DocumentListener() {
                                @Override
                                public void removeUpdate(DocumentEvent e) {
                                    checkAndEnableButtons();
                                }

                                @Override
                                public void insertUpdate(DocumentEvent e) {
                                    checkAndEnableButtons();
                                }

                                @Override
                                public void changedUpdate(DocumentEvent e) {
                                    checkAndEnableButtons();
                                }

                                private void checkAndEnableButtons() {
                                    buttonView.setEnabled(
                                            Desktop.isDesktopSupported()
                                                    && isRootCaCertAvailable());
                                    buttonSave.setEnabled(isRootCaCertAvailable());
                                }
                            });
            JScrollPane scrollPanePem = new JScrollPane(textAreaPem);

            panel = new JPanel();
            GroupLayout layout = new GroupLayout(panel);
            panel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup()
                                            .addGroup(
                                                    layout.createSequentialGroup()
                                                            .addComponent(labelValidity)
                                                            .addComponent(numberSpinnerValidity))
                                            .addGroup(
                                                    layout.createParallelGroup(
                                                                    GroupLayout.Alignment.LEADING)
                                                            .addComponent(labelPem)
                                                            .addComponent(scrollPanePem)))
                            .addGroup(
                                    layout.createParallelGroup()
                                            .addComponent(buttonGenerate)
                                            .addComponent(buttonImport)
                                            .addComponent(buttonView)
                                            .addComponent(buttonSave)));

            layout.setVerticalGroup(
                    layout.createParallelGroup()
                            .addGroup(
                                    layout.createSequentialGroup()
                                            .addGroup(
                                                    layout.createParallelGroup(
                                                                    GroupLayout.Alignment.BASELINE)
                                                            .addComponent(labelValidity)
                                                            .addComponent(numberSpinnerValidity))
                                            .addGroup(
                                                    layout.createSequentialGroup()
                                                            .addComponent(labelPem)
                                                            .addComponent(scrollPanePem)))
                            .addGroup(
                                    layout.createSequentialGroup()
                                            .addComponent(buttonGenerate)
                                            .addComponent(buttonImport)
                                            .addComponent(buttonView)
                                            .addComponent(buttonSave)));
        }

        private static JButton createButton(String name, String iconName, ActionListener action) {
            JButton button =
                    new JButton(
                            Constant.messages.getString(
                                    "network.ui.options.servercertificates.button." + name),
                            DisplayUtils.getScaledIcon(
                                    RootCaCertificatePanel.class.getResource(
                                            "/resource/icon/16/" + iconName)));
            button.addActionListener(action);
            return button;
        }

        JPanel getPanel() {
            return panel;
        }

        void init(ServerCertificatesOptions options) {
            setRootCaCert(options.getRootCaKeyStore());

            numberSpinnerValidity.setValue(options.getRootCaCertValidity().toDays());
        }

        void save(ServerCertificatesOptions options) {
            if (currentRootCaCert != options.getRootCaKeyStore()) {
                options.setRootCaKeyStore(currentRootCaCert);
                extensionNetwork.applyRootCaCert();
            }

            options.setRootCaCertValidity(createValidity(numberSpinnerValidity));
        }

        private void generateRootCaCert() {
            if (!confirmOverwrite()) {
                return;
            }

            try {
                setRootCaCert(
                        CertificateUtils.createRootCaKeyStore(
                                new CertConfig(createValidity(numberSpinnerValidity))));
            } catch (Exception e) {
                LOGGER.error("An error occurred while generating Root CA certificate", e);
            }
        }

        private boolean confirmOverwrite() {
            if (!isRootCaCertAvailable()) {
                return true;
            }

            return JOptionPane.showConfirmDialog(
                            panel,
                            Constant.messages.getString(
                                    "network.ui.options.servercertificates.overwrite.message"),
                            Constant.messages.getString(
                                    "network.ui.options.servercertificates.overwrite.title"),
                            JOptionPane.YES_NO_OPTION)
                    == JOptionPane.YES_OPTION;
        }

        private boolean isRootCaCertAvailable() {
            return textAreaPem.getDocument().getLength() != 0;
        }

        private void saveRootCaCert() {
            JFileChooser fileChooser =
                    new WritableFileChooser(new File(System.getProperty("user.home")));
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            fileChooser.setMultiSelectionEnabled(false);
            fileChooser.setSelectedFile(new File(OWASP_ZAP_ROOT_CA_FILENAME));
            if (fileChooser.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) {
                return;
            }

            Path file = fileChooser.getSelectedFile().toPath();
            LOGGER.info("Saving Root CA certificate to {}", file);
            try {
                writePem(file);
            } catch (IOException e) {
                LOGGER.error(
                        "An error occurred while writing Root CA certificate to file {}", file, e);
            }
        }

        private void writePem(Path file) throws IOException {
            try (BufferedWriter bw = Files.newBufferedWriter(file, StandardCharsets.US_ASCII)) {
                bw.write(textAreaPem.getText());
            }
        }

        private void importRootCaCert() {
            if (!confirmOverwrite()) {
                return;
            }

            JFileChooser fileChooser = new JFileChooser(System.getProperty("user.home"));
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            fileChooser.setMultiSelectionEnabled(false);
            fileChooser.setSelectedFile(new File(CONFIGURATION_FILENAME));
            fileChooser.setFileFilter(
                    new FileFilter() {
                        @Override
                        public String getDescription() {
                            return "config.xml, *.pem";
                        }

                        @Override
                        public boolean accept(File file) {
                            String lcFileName = file.getName().toLowerCase(Locale.ROOT);
                            return lcFileName.endsWith(CONFIGURATION_FILENAME)
                                    || lcFileName.endsWith("pem")
                                    || file.isDirectory();
                        }
                    });
            int result = fileChooser.showOpenDialog(panel);
            if (result != JFileChooser.APPROVE_OPTION) {
                return;
            }

            Path file = fileChooser.getSelectedFile().toPath();
            if (Files.notExists(file)) {
                return;
            }

            LOGGER.info("Loading Root CA certificate from {}", file);
            KeyStore keyStore = null;
            if (file.getFileName().toString().toLowerCase(Locale.ROOT).endsWith("pem")) {
                keyStore = convertPemFileToKeyStore(file);
            } else {
                try {
                    ZapXmlConfiguration conf = new ZapXmlConfiguration(file.toFile());
                    String keyStoreString =
                            conf.getString(ServerCertificatesOptions.ROOT_CA_KEY_STORE);
                    if (keyStoreString == null || keyStoreString.isEmpty()) {
                        JOptionPane.showMessageDialog(
                                panel,
                                Constant.messages.getString(
                                        "network.ui.options.servercertificates.import.config.nocert"),
                                Constant.messages.getString(
                                        "network.ui.options.servercertificates.import.config.nocert.title"),
                                JOptionPane.ERROR_MESSAGE);
                        return;
                    }

                    keyStore = CertificateUtils.stringToKeystore(keyStoreString);
                } catch (Exception e) {
                    LOGGER.warn("Error importing Root CA cert from config file:", e);
                    JOptionPane.showMessageDialog(
                            panel,
                            Constant.messages.getString(
                                    "network.ui.options.servercertificates.import.config.error"),
                            Constant.messages.getString(
                                    "network.ui.options.servercertificates.import.config.error.title"),
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }

            if (keyStore != null) {
                setRootCaCert(keyStore);
            }
        }

        /**
         * Converts the given {@code .pem} file into a {@link KeyStore}.
         *
         * @param pemFile the {@code .pem} file that contains the certificate and the private key.
         * @return the {@code KeyStore} with the certificate, or {@code null} if the conversion
         *     failed.
         */
        private KeyStore convertPemFileToKeyStore(Path pemFile) {
            String pem;
            try {
                pem = new String(Files.readAllBytes(pemFile), StandardCharsets.US_ASCII);
            } catch (IOException e) {
                LOGGER.warn("Failed to read .pem file:", e);
                JOptionPane.showMessageDialog(
                        panel,
                        Constant.messages.getString(
                                "network.importpem.failedreadfile", e.getLocalizedMessage()),
                        Constant.messages.getString("network.importpem.failed.title"),
                        JOptionPane.ERROR_MESSAGE);
                return null;
            }

            byte[] certificate;
            try {
                certificate = CertificateUtils.extractCertificate(pem);
                if (certificate.length == 0) {
                    JOptionPane.showMessageDialog(
                            panel,
                            Constant.messages.getString(
                                    "network.importpem.nocertsection",
                                    CertificateUtils.BEGIN_CERTIFICATE_TOKEN,
                                    CertificateUtils.END_CERTIFICATE_TOKEN),
                            Constant.messages.getString("network.importpem.failed.title"),
                            JOptionPane.ERROR_MESSAGE);
                    return null;
                }
            } catch (IllegalArgumentException e) {
                LOGGER.warn("Failed to base64 decode the certificate from .pem file:", e);
                JOptionPane.showMessageDialog(
                        panel,
                        Constant.messages.getString("network.importpem.certnobase64"),
                        Constant.messages.getString("network.importpem.failed.title"),
                        JOptionPane.ERROR_MESSAGE);
                return null;
            }

            byte[] key;
            try {
                key = CertificateUtils.extractPrivateKey(pem);
                if (key.length == 0) {
                    JOptionPane.showMessageDialog(
                            panel,
                            Constant.messages.getString(
                                    "network.importpem.noprivkeysection",
                                    CertificateUtils.BEGIN_PRIVATE_KEY_TOKEN,
                                    CertificateUtils.END_PRIVATE_KEY_TOKEN),
                            Constant.messages.getString("network.importpem.failed.title"),
                            JOptionPane.ERROR_MESSAGE);
                    return null;
                }
            } catch (IllegalArgumentException e) {
                LOGGER.warn("Failed to base64 decode the private key from .pem file:", e);
                JOptionPane.showMessageDialog(
                        panel,
                        Constant.messages.getString("network.importpem.privkeynobase64"),
                        Constant.messages.getString("network.importpem.failed.title"),
                        JOptionPane.ERROR_MESSAGE);
                return null;
            }

            try {
                return CertificateUtils.pemToKeyStore(certificate, key);
            } catch (Exception e) {
                LOGGER.error("Error creating KeyStore for Root CA cert from .pem file:", e);
                JOptionPane.showMessageDialog(
                        panel,
                        Constant.messages.getString(
                                "network.importpem.failedkeystore", e.getLocalizedMessage()),
                        Constant.messages.getString("network.importpem.failed.title"),
                        JOptionPane.ERROR_MESSAGE);
                return null;
            }
        }

        private void viewRootCaCert() {
            Path file;
            try {
                file = Files.createTempFile(OWASP_ZAP_ROOT_CA_NAME, OWASP_ZAP_ROOT_CA_FILE_EXT);
                writePem(file);
            } catch (IOException e) {
                LOGGER.error("An error occured while creating the temporary file", e);
                return;
            }

            try {
                Desktop.getDesktop().open(file.toFile());
            } catch (IOException e) {
                LOGGER.error("Error while opening {}", file, e);
            }
        }

        private void setRootCaCert(KeyStore rootCaCert) {
            currentRootCaCert = rootCaCert;

            textAreaPem.setText(CertificateUtils.keyStoreToCertificatePem(rootCaCert));
            textAreaPem.setCaretPosition(0);
        }
    }

    private static Duration createValidity(ZapNumberSpinner numberSpinner) {
        return Duration.ofDays(numberSpinner.getValue());
    }

    private static class IssuedCertificatesPanel {

        private final ZapNumberSpinner numberSpinnerValidity;

        private final JPanel panel;

        IssuedCertificatesPanel() {
            JLabel labelValidity =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.servercertificates.field.certvalidity"));
            numberSpinnerValidity =
                    new ZapNumberSpinner(
                            1,
                            ServerCertificatesOptions.DEFAULT_SERVER_CERT_VALIDITY,
                            ServerCertificatesOptions.DEFAULT_SERVER_CERT_VALIDITY * 10);

            panel = new JPanel();
            GroupLayout layout = new GroupLayout(panel);
            panel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addComponent(labelValidity)
                            .addComponent(numberSpinnerValidity));
            layout.setVerticalGroup(
                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(labelValidity)
                            .addComponent(
                                    numberSpinnerValidity,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE));
        }

        JPanel getPanel() {
            return panel;
        }

        void init(ServerCertificatesOptions options) {
            numberSpinnerValidity.setValue(options.getServerCertValidity().toDays());
        }

        void save(ServerCertificatesOptions options) {
            options.setServerCertValidity(createValidity(numberSpinnerValidity));
        }
    }
}
