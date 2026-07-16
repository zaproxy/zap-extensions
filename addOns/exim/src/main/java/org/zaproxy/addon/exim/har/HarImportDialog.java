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
package org.zaproxy.addon.exim.har;

import de.sstoehr.harreader.HarReader;
import de.sstoehr.harreader.HarReaderException;
import de.sstoehr.harreader.model.HarLog;
import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.commonlib.ui.ProgressPane;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class HarImportDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LogManager.getLogger(HarImportDialog.class);
    private static final String THREAD_PREFIX = "ZAP-Import-Har-";
    private static final String TITLE = "exim.har.importDialog.title";
    private static final String FILE_PARAM = "exim.har.importDialog.labelFile";
    private static final String SEND_REQUESTS_PARAM = "exim.har.importDialog.sendRequests";

    private static int threadId = 1;

    public HarImportDialog() {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(500, 180));
        addFileSelectField(
                FILE_PARAM,
                null,
                JFileChooser.FILES_ONLY,
                new FileNameExtensionFilter(
                        Constant.messages.getString("exim.har.file.description"), "har"));
        addCheckBoxField(SEND_REQUESTS_PARAM, false);
        addPadding();
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("exim.har.importDialog.importButton");
    }

    @Override
    public String validateFields() {
        String path = getStringValue(FILE_PARAM);
        if (path.isBlank()) {
            return Constant.messages.getString("exim.har.importDialog.error.missingFile");
        }
        if (!new File(path).canRead()) {
            return Constant.messages.getString("exim.har.importDialog.error.fileNotFound", path);
        }
        return null;
    }

    @Override
    public void save() {
        File file = new File(getStringValue(FILE_PARAM));
        boolean sendRequests = getBoolValue(SEND_REQUESTS_PARAM);
        new Thread(
                        () -> {
                            int tasks = 0;
                            HarLog log = null;
                            try {
                                log = new HarReader().readFromFile(file).log();
                                tasks = log.entries().size();
                            } catch (HarReaderException e) {
                                LOGGER.warn(
                                        "Failed to read HAR file: {}\n{}",
                                        file.getAbsolutePath(),
                                        e.getMessage());
                                HarImporter.DataSource.FILE.error();
                                showImportError(file);
                                return;
                            }
                            ProgressPane currentImportPane =
                                    new ProgressPane(file.getAbsolutePath(), false);
                            currentImportPane.setTotalTasks(tasks);
                            ExtensionExim.getProgressPanel().addProgressPane(currentImportPane);
                            HarImporter harImporter =
                                    new HarImporter(
                                            log,
                                            new ProgressPaneListener(currentImportPane),
                                            sendRequests);
                            if (!harImporter.isSuccess()) {
                                showImportError(file);
                            }
                        },
                        THREAD_PREFIX + threadId++)
                .start();
    }

    private static void showImportError(File file) {
        View.getSingleton()
                .showWarningDialog(
                        Constant.messages.getString(
                                "exim.har.file.import.error", file.getAbsolutePath()));
    }
}
