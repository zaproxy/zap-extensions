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
package org.zaproxy.addon.exim;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.List;
import javax.swing.JFileChooser;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

@SuppressWarnings("serial")
public class PopupMenuExportMessages extends JMenuItem {

    private static final long serialVersionUID = 1L;
    private static final String NEWLINE = "\n";

    private static final Logger LOG = LogManager.getLogger(PopupMenuExportMessages.class);
    private static final String STATS_EXPORT_MESSAGES =
            ExtensionExim.STATS_PREFIX + "export.messages";
    private static final String STATS_EXPORT_MESSAGES_ERROR =
            ExtensionExim.STATS_PREFIX + "export.messages.error";

    private ExtensionHistory extension;

    public PopupMenuExportMessages(ExtensionHistory extension, boolean responsesOnly) {
        if (responsesOnly) {
            setText(Constant.messages.getString("exim.menu.export.responses.popup"));
        } else {
            setText(Constant.messages.getString("exim.menu.export.messages.popup"));
        }
        this.extension = extension;

        this.addActionListener(
                e -> {
                    List<HistoryReference> hrefs = extension.getSelectedHistoryReferences();
                    if (hrefs.isEmpty()) {
                        extension
                                .getView()
                                .showWarningDialog(
                                        Constant.messages.getString(
                                                "exim.menu.export.messages.select.warning"));
                        return;
                    }

                    File file = getOutputFile();
                    if (file == null) {
                        return;
                    }

                    boolean append = true;
                    if (file.exists()) {
                        int rc =
                                extension
                                        .getView()
                                        .showYesNoCancelDialog(
                                                Constant.messages.getString(
                                                        "file.overwrite.warning"));
                        if (rc == JOptionPane.CANCEL_OPTION) {
                            return;
                        } else if (rc == JOptionPane.YES_OPTION) {
                            append = false;
                        }
                    }

                    try (BufferedOutputStream bos =
                            new BufferedOutputStream(new FileOutputStream(file, append)); ) {

                        for (HistoryReference href : hrefs) {
                            HttpMessage msg = null;
                            msg = href.getHttpMessage();
                            exportHistory(msg, bos, responsesOnly);
                        }

                    } catch (Exception e1) {
                        extension
                                .getView()
                                .showWarningDialog(
                                        Constant.messages.getString("file.save.error")
                                                + file.getAbsolutePath()
                                                + ".");
                        LOG.warn(e1.getMessage(), e1);
                    }
                });
    }

    private void exportHistory(HttpMessage msg, BufferedOutputStream bos, boolean responsesOnly) {

        try {
            if (responsesOnly) {
                if (!msg.getResponseHeader().isEmpty()) {
                    bos.write(NEWLINE.getBytes());
                    bos.write("===".getBytes());
                    bos.write(String.valueOf(msg.getHistoryRef().getHistoryId()).getBytes());
                    bos.write(" ==========".getBytes());
                    bos.write(NEWLINE.getBytes());

                    bos.write(msg.getResponseBody().getBytes());
                }
            } else {
                bos.write("===".getBytes());
                bos.write(String.valueOf(msg.getHistoryRef().getHistoryId()).getBytes());
                bos.write(" ==========".getBytes());
                bos.write(NEWLINE.getBytes());
                bos.write(msg.getRequestHeader().toString().getBytes());
                String body = msg.getRequestBody().toString();
                bos.write(body.getBytes());
                if (!body.endsWith(NEWLINE)) {
                    bos.write(NEWLINE.getBytes());
                }

                if (!msg.getResponseHeader().isEmpty()) {
                    bos.write(msg.getResponseHeader().toString().getBytes());
                    body = msg.getResponseBody().toString();
                    bos.write(body.getBytes());
                    if (!body.endsWith(NEWLINE)) {
                        bos.write(NEWLINE.getBytes());
                    }
                }
            }
            Stats.incCounter(STATS_EXPORT_MESSAGES);

        } catch (Exception e) {
            LOG.warn(e.getMessage(), e);
            Stats.incCounter(STATS_EXPORT_MESSAGES_ERROR);
        }
    }

    private File getOutputFile() {

        String filename = "untitled.txt";

        JFileChooser chooser =
                new WritableFileChooser(extension.getModel().getOptionsParam().getUserDirectory());
        if (filename.length() > 0) {
            chooser.setSelectedFile(new File(filename));
        }

        File file = null;
        int rc = chooser.showSaveDialog(extension.getView().getMainFrame());
        if (rc == JFileChooser.APPROVE_OPTION) {
            file = chooser.getSelectedFile();
            if (file == null) {
                return file;
            }

            return file;
        }
        return file;
    }
}
