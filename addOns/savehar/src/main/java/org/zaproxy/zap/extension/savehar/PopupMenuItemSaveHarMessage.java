/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.saveharmessage;

import edu.umass.cs.benchlab.har.HarEntries;
import edu.umass.cs.benchlab.har.HarLog;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.text.MessageFormat;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileFilter;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.HarUtils;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

public class PopupMenuItemSaveHarMessage extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = -7217818541206464572L;

    private static final Logger LOG = Logger.getLogger(PopupMenuItemSaveHarMessage.class);

    private static final String POPUP_MENU_LABEL =
            Constant.messages.getString("savehar.popup.option");
    private static final String HAR_FILE_EXTENSION = ".har";
    private static final String FILE_DESCRIPTION =
            Constant.messages.getString("savehar.file.description");
    private static final String ERROR_SAVE = Constant.messages.getString("savehar.file.save.error");

    public PopupMenuItemSaveHarMessage() {
        super(POPUP_MENU_LABEL);
    }

    @Override
    public void performAction(HttpMessage httpMessage) {
        File file = getOutputFile();
        if (file == null) {
            return;
        }
        try {
            OutputStream os = new BufferedOutputStream(new FileOutputStream(file));
            os.write(packRequestInHarArchive(httpMessage));
            os.flush();
            os.close();
        } catch (IOException e) {
            View.getSingleton()
                    .showWarningDialog(MessageFormat.format(ERROR_SAVE, file.getAbsolutePath()));
            LOG.error(e.getMessage(), e);
        }
    }

    private byte[] packRequestInHarArchive(HttpMessage httpMessage) throws IOException {
        HarLog harLog = HarUtils.createZapHarLog();
        HarEntries entries = new HarEntries();
        entries.addEntry(HarUtils.createHarEntry(httpMessage));
        harLog.setEntries(entries);
        return HarUtils.harLogToByteArray(harLog);
    }

    private static File getOutputFile() {
        SaveHarFileChooser fileChooser = new SaveHarFileChooser();
        int rc = fileChooser.showSaveDialog(View.getSingleton().getMainFrame());
        if (rc == JFileChooser.APPROVE_OPTION) {
            return fileChooser.getSelectedFile();
        }
        return null;
    }

    private static class SaveHarFileChooser extends WritableFileChooser {

        private static final long serialVersionUID = -5743352709683023906L;

        public SaveHarFileChooser() {
            super(Model.getSingleton().getOptionsParam().getUserDirectory());
            setFileFilter(
                    new FileFilter() {
                        @Override
                        public boolean accept(File file) {
                            if (file.isDirectory()) {
                                return true;
                            } else if (file.isFile()
                                    && file.getName().endsWith(HAR_FILE_EXTENSION)) {
                                return true;
                            }
                            return false;
                        }

                        @Override
                        public String getDescription() {
                            return FILE_DESCRIPTION;
                        }
                    });
        }

        @Override
        public void approveSelection() {
            File file = getSelectedFile();
            if (file != null) {
                String fileName = file.getAbsolutePath();
                if (!fileName.endsWith(HAR_FILE_EXTENSION)) {
                    fileName += HAR_FILE_EXTENSION;
                    setSelectedFile(new File(fileName));
                }
            }

            super.approveSelection();
        }
    }
}
