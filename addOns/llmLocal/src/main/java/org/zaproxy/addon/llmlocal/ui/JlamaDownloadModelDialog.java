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
package org.zaproxy.addon.llmlocal.ui;

import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.llmlocal.JlamaHuggingFaceCatalog;
import org.zaproxy.addon.llmlocal.JlamaModelDownloader;
import org.zaproxy.addon.llmlocal.JlamaModelPath;
import org.zaproxy.addon.llmlocal.JlamaRuntime;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.view.LayoutHelper;

/** Dialog to download a HuggingFace SafeTensors model for local Jlama use. */
@SuppressWarnings("serial")
public class JlamaDownloadModelDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = LogManager.getLogger(JlamaDownloadModelDialog.class);

    /** Preferred wrap width for intro/warning labels so the dialog does not grow with long text. */
    private static final int LABEL_WRAP_WIDTH = 420;

    private final JComboBox<String> modelComboBox;
    private final JButton downloadButton;
    private final JButton cancelButton;
    private final JProgressBar progressBar;
    private final AtomicReference<String> downloadedModelId = new AtomicReference<>();
    private final AtomicBoolean downloading = new AtomicBoolean();
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private final AtomicReference<Thread> downloadThread = new AtomicReference<>();
    private final HttpSender httpSender;

    public JlamaDownloadModelDialog(Window parent) {
        super(parent, true);
        setTitle(Constant.messages.getString("llmlocal.download.dialog.title"));
        httpSender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);

        modelComboBox = new JComboBox<>();
        modelComboBox.setEditable(true);
        modelComboBox.setPrototypeDisplayValue(JlamaModelDownloader.DEFAULT_TEST_MODEL);
        modelComboBox.setSelectedItem(JlamaModelDownloader.DEFAULT_TEST_MODEL);

        downloadButton = new JButton(Constant.messages.getString("llmlocal.download.dialog.download"));
        downloadButton.addActionListener(e -> startDownload());

        cancelButton = new JButton(Constant.messages.getString("all.button.cancel"));
        cancelButton.addActionListener(e -> onCancel());

        progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        progressBar.setVisible(false);

        setLayout(new GridBagLayout());
        int row = 0;
        add(
                wrappingLabel(Constant.messages.getString("llmlocal.download.dialog.intro")),
                LayoutHelper.getGBC(0, row++, 2, 1.0, new Insets(8, 8, 4, 8)));
        add(
                new JLabel(Constant.messages.getString("llmlocal.download.dialog.model")),
                LayoutHelper.getGBC(0, row, 1, 0.0, new Insets(4, 8, 4, 4)));
        add(modelComboBox, LayoutHelper.getGBC(1, row++, 1, 1.0, new Insets(4, 4, 4, 8)));
        add(
                wrappingLabel(Constant.messages.getString("llmlocal.download.dialog.warning")),
                LayoutHelper.getGBC(0, row++, 2, 1.0, new Insets(0, 8, 8, 8)));
        add(progressBar, LayoutHelper.getGBC(0, row++, 2, 1.0, new Insets(4, 8, 4, 8)));

        JPanel buttons = new JPanel(new GridBagLayout());
        buttons.add(downloadButton, LayoutHelper.getGBC(0, 0, 1, 0.0, new Insets(4, 4, 4, 4)));
        buttons.add(cancelButton, LayoutHelper.getGBC(1, 0, 1, 0.0, new Insets(4, 4, 4, 4)));
        add(buttons, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(4, 8, 8, 8)));

        pack();
        setMinimumSize(getPreferredSize());
        centreDialog();

        loadCatalogInBackground();
    }

    private static ZapHtmlLabel wrappingLabel(String text) {
        int width = DisplayUtils.getScaledSize(LABEL_WRAP_WIDTH);
        return new ZapHtmlLabel("<html><body width=\"" + width + "\">" + text + "</body></html>");
    }

    /**
     * Shows the dialog and returns the downloaded HuggingFace model id if successful.
     *
     * @param parent the parent window
     * @return the model id, or empty if cancelled / failed
     */
    public static Optional<String> showDialog(Window parent) {
        JlamaDownloadModelDialog dialog = new JlamaDownloadModelDialog(parent);
        dialog.setVisible(true);
        return Optional.ofNullable(dialog.downloadedModelId.get());
    }

    private void onCancel() {
        if (downloading.get()) {
            cancelInProgressDownload();
            return;
        }
        downloadedModelId.set(null);
        dispose();
    }

    private void cancelInProgressDownload() {
        cancelled.set(true);
        Thread thread = downloadThread.get();
        if (thread != null) {
            thread.interrupt();
        }
    }

    private void loadCatalogInBackground() {
        new Thread(
                        () -> {
                            try {
                                List<String> models =
                                        JlamaHuggingFaceCatalog.listTjakeModels(httpSender);
                                ThreadUtils.invokeAndWaitHandled(
                                        () -> {
                                            if (!isDisplayable()) {
                                                return;
                                            }
                                            Object current = modelComboBox.getSelectedItem();
                                            DefaultComboBoxModel<String> model =
                                                    new DefaultComboBoxModel<>();
                                            for (String id : models) {
                                                model.addElement(id);
                                            }
                                            modelComboBox.setModel(model);
                                            if (current != null
                                                    && StringUtils.isNotBlank(current.toString())) {
                                                modelComboBox.setSelectedItem(current.toString());
                                            } else if (model.getSize() > 0) {
                                                modelComboBox.setSelectedItem(
                                                        JlamaModelDownloader.DEFAULT_TEST_MODEL);
                                            }
                                        });
                            } catch (Exception e) {
                                LOGGER.warn(
                                        "Failed to load HuggingFace catalog: {}", e.getMessage());
                                ThreadUtils.invokeAndWaitHandled(
                                        () -> {
                                            if (isDisplayable()) {
                                                View.getSingleton()
                                                        .showWarningDialog(
                                                                this,
                                                                Constant.messages.getString(
                                                                        "llmlocal.download.dialog.catalog.fail",
                                                                        e.getMessage()));
                                            }
                                        });
                            }
                        },
                        "ZAP-Jlama-HF-Catalog")
                .start();
    }

    private void startDownload() {
        String modelId = StringUtils.trimToEmpty(String.valueOf(modelComboBox.getSelectedItem()));
        if (modelId.isEmpty()) {
            View.getSingleton()
                    .showWarningDialog(
                            this, Constant.messages.getString("llmlocal.download.dialog.error.empty"));
            return;
        }
        try {
            JlamaModelDownloader.validateModelId(modelId);
        } catch (IllegalArgumentException e) {
            View.getSingleton()
                    .showWarningDialog(
                            this,
                            Constant.messages.getString(
                                    "llmlocal.download.dialog.error.invalid", e.getMessage()));
            return;
        }

        Path modelDir = JlamaModelPath.resolveModelDirectory(modelId);
        cancelled.set(false);
        setBusy(true);
        Thread thread =
                new Thread(
                        () -> {
                            try {
                                JlamaRuntime.withAddOnClassLoader(
                                        () -> {
                                            try {
                                                JlamaModelDownloader.download(
                                                        JlamaModelPath.getModelsDirectory(),
                                                        modelId,
                                                        (file, current, total) -> {
                                                            if (cancelled.get()
                                                                    || Thread.currentThread()
                                                                            .isInterrupted()) {
                                                                throw new CancellationException(
                                                                        "Download cancelled");
                                                            }
                                                        });
                                                return null;
                                            } catch (CancellationException e) {
                                                throw e;
                                            } catch (Exception e) {
                                                if (cancelled.get() || isCancellation(e)) {
                                                    throw new CancellationException(
                                                            "Download cancelled");
                                                }
                                                throw new RuntimeException(e);
                                            }
                                        });
                                if (cancelled.get()) {
                                    cleanupCancelledDownload(modelDir);
                                    return;
                                }
                                ThreadUtils.invokeAndWaitHandled(
                                        () -> {
                                            downloadedModelId.set(modelId);
                                            dispose();
                                        });
                            } catch (CancellationException e) {
                                cleanupCancelledDownload(modelDir);
                            } catch (Exception e) {
                                if (cancelled.get() || isCancellation(e)) {
                                    cleanupCancelledDownload(modelDir);
                                    return;
                                }
                                Throwable cause = e;
                                if (e instanceof RuntimeException && e.getCause() != null) {
                                    cause = e.getCause();
                                }
                                if (isCancellation(cause)) {
                                    cleanupCancelledDownload(modelDir);
                                    return;
                                }
                                LOGGER.error("Failed to download Jlama model {}", modelId, cause);
                                Throwable error = cause;
                                ThreadUtils.invokeAndWaitHandled(
                                        () -> {
                                            setBusy(false);
                                            View.getSingleton()
                                                    .showWarningDialog(
                                                            this,
                                                            Constant.messages.getString(
                                                                    "llmlocal.download.dialog.error.download",
                                                                    modelId,
                                                                    error.getMessage()));
                                        });
                            } finally {
                                downloadThread.compareAndSet(Thread.currentThread(), null);
                            }
                        },
                        "ZAP-Jlama-HF-Download");
        downloadThread.set(thread);
        thread.start();
    }

    private void cleanupCancelledDownload(Path modelDir) {
        JlamaModelDownloader.deleteIncompleteDownload(modelDir);
        ThreadUtils.invokeAndWaitHandled(
                () -> {
                    if (isDisplayable()) {
                        setBusy(false);
                    }
                });
    }

    private static boolean isCancellation(Throwable throwable) {
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (current instanceof CancellationException
                    || current instanceof InterruptedException) {
                return true;
            }
            String message = current.getMessage();
            if (message != null && message.toLowerCase().contains("cancel")) {
                return true;
            }
        }
        return false;
    }

    private void setBusy(boolean busy) {
        downloading.set(busy);
        progressBar.setVisible(busy);
        downloadButton.setEnabled(!busy);
        modelComboBox.setEnabled(!busy);
        // Cancel stays enabled so an in-progress download can be aborted.
        pack();
    }
}
