/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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

import java.awt.event.ItemEvent;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.security.KeyStoreException;
import java.security.ProviderException;
import java.security.cert.Certificate;
import java.util.function.BiConsumer;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXHyperlink;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.network.internal.client.CertificateEntry;
import org.zaproxy.addon.network.internal.client.KeyStoreEntry;
import org.zaproxy.addon.network.internal.client.KeyStoreEntry.Type;
import org.zaproxy.addon.network.internal.client.KeyStores;
import org.zaproxy.addon.network.internal.client.KeyStoresException;
import org.zaproxy.addon.network.internal.client.Pkcs11Driver;
import org.zaproxy.addon.network.internal.ui.CertificateDialog;
import org.zaproxy.addon.network.internal.ui.CertificatesTableModel;
import org.zaproxy.addon.network.internal.ui.ConsumerDocumentListener;
import org.zaproxy.addon.network.internal.ui.DriversComboBoxModel;
import org.zaproxy.addon.network.internal.ui.KeyStoresTableModel;
import org.zaproxy.addon.network.internal.ui.Pkcs11DriversDialog;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.ZapTable;

@SuppressWarnings("serial")
class ClientCertificatesOptionsPanel extends AbstractParamPanel {

    private static final Logger LOGGER = LogManager.getLogger(ClientCertificatesOptionsPanel.class);

    private static final long serialVersionUID = 1L;

    private final JCheckBox useCertificate;
    private final JTabbedPane tabbedPane;
    private final Pkcs12Panel pkcs12Panel;
    private final Pkcs11Panel pkcs11Panel;
    private final KeyStorePanel keyStorePanel;

    public ClientCertificatesOptionsPanel(View view) {
        tabbedPane = new JTabbedPane();
        keyStorePanel = new KeyStorePanel(view);
        keyStorePanel.setTabSelector(this::selectKeyStoreTab);
        pkcs12Panel = new Pkcs12Panel(view, keyStorePanel::addPkcs12KeyStore);
        pkcs11Panel = new Pkcs11Panel(view, keyStorePanel::addPkcs11KeyStore);

        setName(Constant.messages.getString("network.ui.options.clientcertificates.name"));

        tabbedPane.add(
                Constant.messages.getString("network.ui.options.clientcertificates.pkcs12.tab"),
                pkcs12Panel.getPanel());
        tabbedPane.add(
                Constant.messages.getString("network.ui.options.clientcertificates.pkcs11.tab"),
                pkcs11Panel.getPanel());
        tabbedPane.add(
                Constant.messages.getString("network.ui.options.clientcertificates.keystore.tab"),
                keyStorePanel.getPanel());

        useCertificate =
                new JCheckBox(
                        Constant.messages.getString(
                                "network.ui.options.clientcertificates.usecertificate"),
                        true);
        useCertificate.addItemListener(
                e -> {
                    boolean state = e.getStateChange() == ItemEvent.SELECTED;
                    pkcs12Panel.setEnabled(state);
                    pkcs11Panel.setEnabled(state);
                    keyStorePanel.setEnabled(state);
                    tabbedPane.setEnabled(state);
                });
        useCertificate.setSelected(false);

        JLabel descriptionLabel =
                new JLabel(
                        Constant.messages.getString(
                                "network.ui.options.clientcertificates.description"));

        GroupLayout mainLayout = new GroupLayout(this);
        setLayout(mainLayout);
        mainLayout.setAutoCreateGaps(true);
        mainLayout.setAutoCreateContainerGaps(true);

        mainLayout.setHorizontalGroup(
                mainLayout
                        .createParallelGroup()
                        .addComponent(descriptionLabel)
                        .addComponent(useCertificate)
                        .addComponent(tabbedPane));
        mainLayout.setVerticalGroup(
                mainLayout
                        .createSequentialGroup()
                        .addComponent(descriptionLabel)
                        .addComponent(useCertificate)
                        .addComponent(tabbedPane));
    }

    private void selectKeyStoreTab() {
        tabbedPane.setSelectedComponent(keyStorePanel.getPanel());
    }

    @Override
    public void initParam(Object mainOptions) {
        ClientCertificatesOptions options = getClientCertificatesOptions(mainOptions);

        pkcs12Panel.init(options);
        pkcs11Panel.init(options);
        keyStorePanel.init(options);

        useCertificate.setSelected(options.isUseCertificate());
    }

    private static ClientCertificatesOptions getClientCertificatesOptions(Object mainOptions) {
        return ((OptionsParam) mainOptions).getParamSet(ClientCertificatesOptions.class);
    }

    @Override
    public void saveParam(Object mainOptions) throws Exception {
        ClientCertificatesOptions options = getClientCertificatesOptions(mainOptions);

        pkcs12Panel.save(options);
        pkcs11Panel.save(options);
        keyStorePanel.save(options);

        options.setUseCertificate(useCertificate.isSelected());
    }

    @Override
    public String getHelpIndex() {
        return "addon.network.options.clientcertificates";
    }

    private static class Pkcs12Panel {

        private final ZapTextField fileTextField;
        private final JButton fileChooserButton;
        private final JPasswordField passwordField;
        private final JCheckBox storeCheckBox;
        private final JButton addKeyStoreButton;

        private final JPanel panel;

        Pkcs12Panel(View view, BiConsumer<String, String> addCertConsumer) {
            JLabel fileLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.pkcs12.file"));
            fileTextField = new ZapTextField();
            fileLabel.setLabelFor(fileTextField);

            fileChooserButton =
                    new JButton(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.pkcs12.file.select"));
            fileChooserButton.addActionListener(
                    e -> {
                        JFileChooser fileChooser = new JFileChooser();
                        fileChooser.setFileFilter(
                                new FileNameExtensionFilter(
                                        Constant.messages.getString(
                                                "network.ui.options.clientcertificates.pkcs12.file.select.desc",
                                                "(*.p12, *.pfx)"),
                                        "p12",
                                        "pfx"));
                        fileChooser.setSelectedFile(new File(fileTextField.getText()));

                        if (fileChooser.showOpenDialog(view.getOptionsDialog(null))
                                == JFileChooser.APPROVE_OPTION) {
                            fileTextField.setText(fileChooser.getSelectedFile().toString());
                        }
                    });

            passwordField = new JPasswordField();
            JLabel passwordLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.pkcs12.password"));
            passwordLabel.setLabelFor(passwordField);

            storeCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.pkcs12.store"));

            addKeyStoreButton =
                    new JButton(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.addkeystore"));
            addKeyStoreButton.addActionListener(
                    e ->
                            addCertConsumer.accept(
                                    fileTextField.getText(),
                                    new String(passwordField.getPassword())));
            addKeyStoreButton.setEnabled(false);

            ConsumerDocumentListener documentListener =
                    new ConsumerDocumentListener(e -> setAddToKeyStoreButtonEnabled(true));
            fileTextField.getDocument().addDocumentListener(documentListener);
            passwordField.getDocument().addDocumentListener(documentListener);

            panel = new JPanel();
            GroupLayout layout = new GroupLayout(panel);
            panel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            layout.setHorizontalGroup(
                    layout.createParallelGroup()
                            .addGroup(
                                    layout.createSequentialGroup()
                                            .addGroup(
                                                    layout.createParallelGroup(
                                                                    GroupLayout.Alignment.TRAILING)
                                                            .addComponent(fileLabel)
                                                            .addComponent(passwordLabel))
                                            .addGroup(
                                                    layout.createParallelGroup(
                                                                    GroupLayout.Alignment.LEADING)
                                                            .addGroup(
                                                                    layout.createSequentialGroup()
                                                                            .addComponent(
                                                                                    fileTextField)
                                                                            .addComponent(
                                                                                    fileChooserButton))
                                                            .addComponent(passwordField)
                                                            .addComponent(storeCheckBox)))
                            .addComponent(addKeyStoreButton, GroupLayout.Alignment.TRAILING));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(fileLabel)
                                            .addComponent(fileTextField)
                                            .addComponent(fileChooserButton))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(passwordLabel)
                                            .addComponent(passwordField))
                            .addComponent(storeCheckBox)
                            .addComponent(addKeyStoreButton));
        }

        private void setAddToKeyStoreButtonEnabled(boolean enabled) {
            addKeyStoreButton.setEnabled(
                    enabled
                            && fileTextField.getDocument().getLength() != 0
                            && passwordField.getDocument().getLength() != 0);
        }

        JPanel getPanel() {
            return panel;
        }

        void setEnabled(boolean enabled) {
            fileTextField.setEnabled(enabled);
            fileChooserButton.setEnabled(enabled);
            passwordField.setEnabled(enabled);
            storeCheckBox.setEnabled(enabled);
            setAddToKeyStoreButtonEnabled(enabled);
        }

        void init(ClientCertificatesOptions options) {
            fileTextField.setText(options.getPkcs12File());
            fileTextField.discardAllEdits();
            passwordField.setText(options.getPkcs12Password());
            storeCheckBox.setSelected(options.isPkcs12Store());
        }

        void save(ClientCertificatesOptions options) {
            options.setPkcs12File(fileTextField.getText());
            options.setPkcs12Password(new String(passwordField.getPassword()));
            options.setPkcs12Store(storeCheckBox.isSelected());
        }
    }

    private static class Pkcs11Panel {

        private final JComboBox<Pkcs11Driver> driversComboBox;
        private final DriversComboBoxModel driversComboBoxModel;
        private final JButton manageDriversButton;
        private final JPasswordField pinField;
        private final JCheckBox useSliCheckBox;
        private final JButton addKeyStoreButton;
        private final Pkcs11DriversDialog pkcs11DriversDialog;

        private final JPanel panel;

        Pkcs11Panel(View view, AddPkcs11KeyStore addKeyStoreConsumer) {
            pkcs11DriversDialog = new Pkcs11DriversDialog(view.getOptionsDialog(null));

            driversComboBoxModel = new DriversComboBoxModel(pkcs11DriversDialog.getDrivers());

            JLabel driverLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.pkcs11.driver"));
            driversComboBox = new JComboBox<>(driversComboBoxModel);
            driverLabel.setLabelFor(driversComboBox);
            driversComboBox.addItemListener(e -> setAddToKeyStoreButtonEnabled(true));

            manageDriversButton =
                    new JButton(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.pkcs11.driver.manage"));
            manageDriversButton.addActionListener(
                    e -> {
                        pkcs11DriversDialog.setVisible(true);
                        setAddToKeyStoreButtonEnabled(true);
                    });

            pinField = new JPasswordField();
            JLabel pinLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.pkcs11.pin"));
            pinLabel.setLabelFor(pinField);

            useSliCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.pkcs11.usesli"));

            addKeyStoreButton =
                    new JButton(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.addkeystore"));
            addKeyStoreButton.addActionListener(
                    e ->
                            addKeyStoreConsumer.accept(
                                    (Pkcs11Driver) driversComboBox.getSelectedItem(),
                                    new String(pinField.getPassword()),
                                    useSliCheckBox.isSelected()));
            addKeyStoreButton.setEnabled(false);

            panel = new JPanel();
            GroupLayout layout = new GroupLayout(panel);
            panel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            layout.setHorizontalGroup(
                    layout.createParallelGroup()
                            .addGroup(
                                    layout.createSequentialGroup()
                                            .addGroup(
                                                    layout.createParallelGroup(
                                                                    GroupLayout.Alignment.TRAILING)
                                                            .addComponent(driverLabel)
                                                            .addComponent(pinLabel))
                                            .addGroup(
                                                    layout.createParallelGroup(
                                                                    GroupLayout.Alignment.LEADING)
                                                            .addGroup(
                                                                    layout.createSequentialGroup()
                                                                            .addComponent(
                                                                                    driversComboBox)
                                                                            .addComponent(
                                                                                    manageDriversButton))
                                                            .addComponent(pinField)
                                                            .addComponent(useSliCheckBox)))
                            .addComponent(addKeyStoreButton, GroupLayout.Alignment.TRAILING));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(driverLabel)
                                            .addComponent(driversComboBox)
                                            .addComponent(manageDriversButton))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(pinLabel)
                                            .addComponent(pinField))
                            .addComponent(useSliCheckBox)
                            .addComponent(addKeyStoreButton));
        }

        private void setAddToKeyStoreButtonEnabled(boolean enabled) {
            addKeyStoreButton.setEnabled(enabled && driversComboBox.getSelectedIndex() != -1);
        }

        JPanel getPanel() {
            return panel;
        }

        void setEnabled(boolean enabled) {
            driversComboBox.setEnabled(enabled);
            manageDriversButton.setEnabled(enabled);
            pinField.setEnabled(enabled);
            useSliCheckBox.setEnabled(enabled);
            setAddToKeyStoreButtonEnabled(enabled);
        }

        void init(ClientCertificatesOptions options) {
            useSliCheckBox.setSelected(options.isPkcs11UseSlotListIndex());
        }

        void save(ClientCertificatesOptions options) {
            options.setPkcs11UseSlotListIndex(useSliCheckBox.isSelected());
        }
    }

    private static class KeyStorePanel {

        // Maximum number of login attempts per smartcard
        private static final int MAX_LOGIN_ATTEMPTS = 3;

        private final KeyStoresTableModel keyStoresTableModel;
        private final ZapTable keyStoresTable;
        private final JButton removeKeyStoreButton;
        private final CertificatesTableModel certificatesTableModel;
        private final ZapTable certificatesTable;
        private final JButton activateCertificateButton;
        private final JButton viewCertificateButton;
        private final JTextField activeCertificateField;
        private final JButton viewActiveCertificateButton;

        private final JPanel panel;
        private final View view;
        private boolean firstInit;
        private Runnable selectOwnTab;

        private KeyStores keyStores;

        private boolean retry;
        private int loginAttempts;

        KeyStorePanel(View view) {
            this.view = view;
            firstInit = true;
            retry = true;

            keyStoresTableModel = new KeyStoresTableModel();
            keyStoresTable = new ZapTable(keyStoresTableModel);
            keyStoresTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            keyStoresTable.setVisibleRowCount(10);
            JScrollPane keyStoresScrollPane = new JScrollPane(keyStoresTable);

            certificatesTableModel = new CertificatesTableModel();
            certificatesTable = new ZapTable(certificatesTableModel);
            certificatesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            JScrollPane aliasesScrollPane = new JScrollPane(certificatesTable);

            activateCertificateButton =
                    new JButton(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.keystore.activate"));
            activateCertificateButton.setEnabled(false);
            activateCertificateButton.addActionListener(e -> activateSelectedCertificate());

            viewCertificateButton =
                    new JButton(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.keystore.view"));
            viewCertificateButton.setEnabled(false);
            viewCertificateButton.addActionListener(e -> viewSelectedCertificate());

            keyStoresTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            evt -> {
                                int index = getSelectedRow(keyStoresTable);
                                if (index == -1) {
                                    return;
                                }

                                try {
                                    KeyStoreEntry entry = keyStores.get(index);
                                    certificatesTableModel.setCertificates(entry.getCertificates());
                                    boolean hasEntries = certificatesTableModel.getRowCount() != 0;
                                    if (hasEntries) {
                                        certificatesTable.setRowSelectionInterval(0, 0);
                                    }
                                    activateCertificateButton.setEnabled(hasEntries);
                                    viewCertificateButton.setEnabled(hasEntries);
                                } catch (Exception e) {
                                    showKeyStoreCertError(view, e.toString());
                                    LOGGER.error(e.getMessage(), e);
                                }
                            });

            viewActiveCertificateButton =
                    new JButton(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.keystore.view"));
            viewActiveCertificateButton.setEnabled(false);
            viewActiveCertificateButton.addActionListener(
                    e -> showCertificate(keyStores.getActiveCertificate().getCertificate()));

            JLabel activeCertificateLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.keystore.activecertificate"));
            activeCertificateField = new JTextField();
            activeCertificateField.setEditable(false);
            activeCertificateLabel.setLabelFor(activeCertificateField);

            removeKeyStoreButton =
                    new JButton(
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.keystore.remove"));
            removeKeyStoreButton.setEnabled(false);

            removeKeyStoreButton.addActionListener(
                    e -> {
                        int index = getSelectedRow(keyStoresTable);
                        if (index == -1) {
                            return;
                        }

                        keyStores.remove(index);
                        certificatesTableModel.clear();
                        activateCertificateButton.setEnabled(false);
                        viewCertificateButton.setEnabled(false);

                        boolean hasEntries = keyStoresTableModel.getRowCount() != 0;
                        if (hasEntries) {
                            keyStoresTable.setRowSelectionInterval(0, 0);
                            certificatesTable.requestFocusInWindow();
                        }
                        removeKeyStoreButton.setEnabled(hasEntries);

                        updateActiveCertificate();
                    });

            panel = new JPanel();
            GroupLayout layout = new GroupLayout(panel);
            panel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            layout.setHorizontalGroup(
                    layout.createParallelGroup()
                            .addGroup(
                                    layout.createSequentialGroup()
                                            .addComponent(keyStoresScrollPane)
                                            .addComponent(removeKeyStoreButton))
                            .addGroup(
                                    layout.createSequentialGroup()
                                            .addComponent(aliasesScrollPane)
                                            .addGroup(
                                                    layout.createParallelGroup()
                                                            .addComponent(activateCertificateButton)
                                                            .addComponent(viewCertificateButton)))
                            .addComponent(activeCertificateLabel)
                            .addGroup(
                                    layout.createSequentialGroup()
                                            .addComponent(activeCertificateField)
                                            .addComponent(viewActiveCertificateButton)));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup()
                                            .addComponent(keyStoresScrollPane)
                                            .addComponent(removeKeyStoreButton))
                            .addGroup(
                                    layout.createParallelGroup()
                                            .addComponent(aliasesScrollPane)
                                            .addGroup(
                                                    layout.createSequentialGroup()
                                                            .addComponent(activateCertificateButton)
                                                            .addComponent(viewCertificateButton)))
                            .addComponent(activeCertificateLabel)
                            .addGroup(
                                    layout.createParallelGroup()
                                            .addComponent(
                                                    activeCertificateField,
                                                    GroupLayout.PREFERRED_SIZE,
                                                    GroupLayout.PREFERRED_SIZE,
                                                    GroupLayout.PREFERRED_SIZE)
                                            .addComponent(viewActiveCertificateButton)));

            layout.linkSize(
                    SwingConstants.HORIZONTAL,
                    removeKeyStoreButton,
                    activateCertificateButton,
                    viewCertificateButton,
                    viewActiveCertificateButton);
        }

        private static int getSelectedRow(ZapTable table) {
            int selectedRow = table.getSelectedRow();
            if (selectedRow == -1) {
                return selectedRow;
            }
            return table.convertRowIndexToModel(selectedRow);
        }

        JPanel getPanel() {
            return panel;
        }

        void setEnabled(boolean enabled) {
            keyStoresTable.setEnabled(enabled);
            removeKeyStoreButton.setEnabled(enabled && keyStoresTableModel.getRowCount() != 0);
            certificatesTable.setEnabled(enabled);
            boolean aliases = enabled && certificatesTableModel.getRowCount() != 0;
            activateCertificateButton.setEnabled(aliases);
            viewCertificateButton.setEnabled(aliases);
            activeCertificateField.setEnabled(enabled);
            viewActiveCertificateButton.setEnabled(
                    enabled && keyStores != null && keyStores.getActiveCertificate() != null);
        }

        void setTabSelector(Runnable selectOwnTab) {
            this.selectOwnTab = selectOwnTab;
        }

        void init(ClientCertificatesOptions options) {
            keyStores = options.getKeyStores();

            keyStoresTableModel.setKeyStores(keyStores);
            if (keyStoresTableModel.getRowCount() != 0) {
                keyStoresTable.setRowSelectionInterval(0, 0);
            }
            updateActiveCertificate();

            if (firstInit) {
                if (keyStoresTableModel.getRowCount() != 0) {
                    selectOwnTab.run();
                }
                firstInit = false;
            }
        }

        private void updateActiveCertificate() {
            CertificateEntry certificate = keyStores.getActiveCertificate();
            String key = null;
            if (certificate != null) {
                key = certificate.getName();
            }
            activeCertificateField.setText(key);
            viewActiveCertificateButton.setEnabled(certificate != null);
        }

        void save(ClientCertificatesOptions options) {
            CertificateEntry activeCertificate = keyStores.getActiveCertificate();
            if (activeCertificate != null
                    && activeCertificate.getParent().getType() == Type.PKCS12) {
                options.setPkcs12Index(activeCertificate.getIndex());
            }
        }

        void addPkcs12KeyStore(String file, String password) {
            try {
                keyStores.addPkcs12KeyStore(file, password);
                int index = keyStores.size() - 1;
                keyStoreAdded(index);

            } catch (Exception e) {
                showKeyStoreCertError(
                        view,
                        Constant.messages.getString(
                                "network.ui.options.clientcertificates.error.pkcs12.wrongdata"));
                LOGGER.warn(e.getMessage(), e);
            }
        }

        void addPkcs11KeyStore(Pkcs11Driver driver, String pin, boolean useSlotListIndex) {
            String name = driver.getName();
            String password = pin.isEmpty() ? null : pin;
            Throwable cause;
            try {
                KeyStoreEntry keyStoreEntry =
                        keyStores.addPkcs11KeyStore(
                                driver.getName(),
                                driver.getConfiguration(useSlotListIndex),
                                password);

                if (keyStoreEntry == null) {
                    LOGGER.error(
                            "The required PKCS#11 provider is not available ({} or {}).",
                            KeyStores.SUN_PKCS11_CANONICAL_CLASS_NAME,
                            KeyStores.IBM_PKCS11_CANONICAL_CLASS_NAME);
                    showErrorMessageSunPkcs11ProviderNotAvailable(view);
                    return;
                }

                int index = keyStores.size() - 1;
                keyStoreAdded(index);

                loginAttempts = 0;
                retry = true;
                return;
            } catch (KeyStoresException e) {
                cause = e.getCause();
            }

            if (cause instanceof InvocationTargetException) {
                if (cause.getCause() instanceof ProviderException) {
                    if ("Error parsing configuration".equals(cause.getCause().getMessage())) {
                        // There was a problem with the configuration provided:
                        //   - Missing library.
                        //   - Malformed configuration.
                        //   - ...
                        logAndShowGenericErrorMessagePkcs11CouldNotBeAdded(
                                view, false, name, pin, cause);
                        return;
                    }

                    if ("Initialization failed".equals(cause.getCause().getMessage())) {
                        // The initialisation may fail because of:
                        //   - no smart card reader or smart card detected.
                        //   - smart card is in use by other application.
                        //   - ...

                        if (retry) {
                            retry = false;
                            addPkcs11KeyStore(driver, pin, useSlotListIndex);
                            return;
                        }
                        showClientCertError(
                                view,
                                Constant.messages.getString(
                                        "network.ui.options.clientcertificates.error.pkcs11.lib"));
                        retry = true;
                        LOGGER.warn("Couldn't add key from {}", name, cause);
                        return;
                    }
                    logAndShowGenericErrorMessagePkcs11CouldNotBeAdded(
                            view, false, name, pin, cause);
                    return;
                }
                logAndShowGenericErrorMessagePkcs11CouldNotBeAdded(view, false, name, pin, cause);

                return;
            }

            if (cause instanceof IOException) {
                if (cause.getMessage().equals("load failed")
                        && cause.getCause()
                                .getClass()
                                .getName()
                                .equals("javax.security.auth.login.FailedLoginException")) {
                    // Exception due to a failed login attempt: BAD PIN or password
                    loginAttempts++;
                    String attempts = " (" + loginAttempts + "/" + MAX_LOGIN_ATTEMPTS + ") ";
                    if (loginAttempts == (MAX_LOGIN_ATTEMPTS - 1)) {
                        // Last attempt before blocking the smartcard
                        showClientCertError(
                                view,
                                Constant.messages.getString(
                                        "network.ui.options.clientcertificates.error.pkcs11.wrongpassword"),
                                Constant.messages.getString(
                                        "network.ui.options.clientcertificates.error.pkcs11.wrongpasswordlast"),
                                attempts);
                        LOGGER.warn(
                                "PKCS#11: Incorrect PIN or password{}: {} *LAST TRY BEFORE BLOCKING*",
                                attempts,
                                name);
                        return;
                    }
                    showClientCertError(
                            view,
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.error.pkcs11.wrongpassword"),
                            attempts);
                    LOGGER.warn("PKCS#11: Incorrect PIN or password{}: {}", attempts, name);
                    return;
                }
                logAndShowGenericErrorMessagePkcs11CouldNotBeAdded(view, false, name, pin, cause);
                return;
            }

            if (cause instanceof KeyStoreException) {
                logAndShowGenericErrorMessagePkcs11CouldNotBeAdded(view, false, name, pin, cause);
                return;
            }

            logAndShowGenericErrorMessagePkcs11CouldNotBeAdded(view, true, name, pin, cause);
        }

        private static void showErrorMessageSunPkcs11ProviderNotAvailable(View view) {
            final String sunReference =
                    Constant.messages.getString(
                            "network.ui.options.clientcertificates.error.pkcs11.notavailable.sun.hyperlink");
            final String ibmReference =
                    Constant.messages.getString(
                            "network.ui.options.clientcertificates.error.pkcs11.notavailable.ibm.hyperlink");
            Object[] hyperlinks = new Object[2];
            try {
                JXHyperlink hyperlinkLabel = new JXHyperlink();
                hyperlinkLabel.setURI(URI.create(sunReference));
                hyperlinkLabel.setText(
                        Constant.messages.getString(
                                "network.ui.options.clientcertificates.error.pkcs11.notavailable.sun.hyperlink.text"));
                hyperlinks[0] = hyperlinkLabel;

                hyperlinkLabel = new JXHyperlink();
                hyperlinkLabel.setURI(URI.create(ibmReference));
                hyperlinkLabel.setText(
                        Constant.messages.getString(
                                "network.ui.options.clientcertificates.error.pkcs11.notavailable.ibm.hyperlink.text"));
                hyperlinks[1] = hyperlinkLabel;
            } catch (UnsupportedOperationException e) {
                hyperlinks[0] = sunReference;
                hyperlinks[1] = ibmReference;
            }

            showClientCertError(
                    view,
                    Constant.messages.getString(
                            "network.ui.options.clientcertificates.error.pkcs11.notavailable"),
                    hyperlinks);
        }

        private static void showClientCertError(View view, Object... messages) {
            Object[] allMessages = new Object[messages.length + 1];
            allMessages[0] =
                    Constant.messages.getString("network.ui.options.clientcertificates.error");
            System.arraycopy(messages, 0, allMessages, 1, messages.length);
            JOptionPane.showMessageDialog(
                    view.getOptionsDialog(null),
                    allMessages,
                    Constant.messages.getString(
                            "network.ui.options.clientcertificates.error.cert.title"),
                    JOptionPane.ERROR_MESSAGE);
        }

        private static void logAndShowGenericErrorMessagePkcs11CouldNotBeAdded(
                View view, boolean isErrorLevel, String name, String pin, Throwable e) {
            if (pin.length() == 0) {
                showClientCertError(
                        view,
                        Constant.messages.getString(
                                "network.ui.options.clientcertificates.error.pkcs11.pinempty"));
            } else {
                showClientCertError(
                        view,
                        Constant.messages.getString(
                                "network.ui.options.clientcertificates.error.pkcs11.wrongdata"));
                if (isErrorLevel) {
                    LOGGER.error("Couldn't add key from {}", name, e);
                } else {
                    LOGGER.warn("Couldn't add key from {}", name, e);
                }
            }
        }

        private static void showKeyStoreCertError(View view, String errorMessage) {
            showCertError(
                    view,
                    "network.ui.options.clientcertificates.error.accesskeystore",
                    errorMessage);
        }

        private static void showCertError(
                View view, String i18nKeyBaseMessage, String errorMessage) {
            JOptionPane.showMessageDialog(
                    view.getOptionsDialog(null),
                    new String[] {Constant.messages.getString(i18nKeyBaseMessage), errorMessage},
                    Constant.messages.getString("network.ui.options.clientcertificates.error"),
                    JOptionPane.ERROR_MESSAGE);
        }

        private void keyStoreAdded(int index) {
            selectOwnTab.run();
            certificatesTable.requestFocusInWindow();
            removeKeyStoreButton.setEnabled(keyStoresTableModel.getRowCount() != 0);

            if (index < 0 || index >= keyStoresTableModel.getRowCount()) {
                return;
            }

            int viewIndex = keyStoresTable.convertRowIndexToView(index);
            keyStoresTable.setRowSelectionInterval(viewIndex, viewIndex);
            if (certificatesTable.getRowCount() == 0) {
                return;
            }

            certificatesTable.setRowSelectionInterval(0, 0);

            if (certificatesTable.getRowCount() == 1 && keyStores.getActiveCertificate() == null) {
                activateSelectedCertificate();
            }
        }

        private void activateSelectedCertificate() {
            int alias = getSelectedRow(certificatesTable);
            if (alias == -1) {
                return;
            }

            CertificateEntry certificateEntry = certificatesTableModel.getCertificateEntry(alias);
            if (!certificateEntry.isUnlocked()) {
                try {
                    if (!certificateEntry.unlock(getPassword())) {
                        showKeyStoreCertError(view, "");
                    }
                } catch (Exception e) {
                    showKeyStoreCertError(view, e.toString());
                    LOGGER.warn(e.getMessage(), e);
                    return;
                }
            }

            keyStores.setActiveCertificate(certificateEntry);

            updateActiveCertificate();
        }

        private void viewSelectedCertificate() {
            int row = getSelectedRow(certificatesTable);
            if (row == -1) {
                return;
            }

            showCertificate(certificatesTableModel.getCertificateEntry(row).getCertificate());
        }

        private void showCertificate(Certificate certificate) {
            if (certificate != null) {
                new CertificateDialog(view.getOptionsDialog(null), certificate.toString());
            }
        }

        private String getPassword() {
            JPasswordField askPasswordField = new JPasswordField();
            int result =
                    JOptionPane.showConfirmDialog(
                            view.getOptionsDialog(null),
                            askPasswordField,
                            Constant.messages.getString(
                                    "network.ui.options.clientcertificates.keystore.enterpassword"),
                            JOptionPane.OK_CANCEL_OPTION);
            if (result == JOptionPane.OK_OPTION) {
                return new String(askPasswordField.getPassword());
            }
            return null;
        }
    }

    private interface AddPkcs11KeyStore {
        void accept(Pkcs11Driver driver, String pin, boolean useSlotListIndex);
    }
}
