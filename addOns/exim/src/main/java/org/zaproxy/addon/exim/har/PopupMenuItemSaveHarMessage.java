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
package org.zaproxy.addon.exim.har;

import edu.umass.cs.benchlab.har.HarEntries;
import edu.umass.cs.benchlab.har.HarLog;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.text.MessageFormat;
import java.util.List;
import javax.swing.JFileChooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.exim.EximFileChooser;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.utils.HarUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

public class PopupMenuItemSaveHarMessage extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = -7217818541206464572L;

    private static final Logger LOG = LogManager.getLogger(PopupMenuItemSaveHarMessage.class);
    private static final String STATS_SAVE_HAR_FILE = "save.har.file";
    private static final String STATS_SAVE_HAR_FILE_ERROR = "save.har.file.error";
    private static final String STATS_SAVE_HAR_FILE_MSG = "save.har.file.message";
    private static final String POPUP_MENU_LABEL =
            Constant.messages.getString("exim.har.popup.option");
    private static final String HAR_FILE_EXTENSION = ".har";
    private static final String FILE_DESCRIPTION =
            Constant.messages.getString("exim.har.file.description");
    private static final String ERROR_SAVE =
            Constant.messages.getString("exim.har.file.save.error");

    public PopupMenuItemSaveHarMessage() {
        super(POPUP_MENU_LABEL, true);
    }

    @Override
    public boolean precedeWithSeparator() {
        return true;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    @Override
    protected void performActions(List<HttpMessage> httpMessages) {
        File file = getOutputFile();
        if (file == null) {
            return;
        }
        try (OutputStream os = new BufferedOutputStream(new FileOutputStream(file))) {
            os.write(packRequestInHarArchive(httpMessages));
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_SAVE_HAR_FILE);
        } catch (IOException e) {
            View.getSingleton()
                    .showWarningDialog(MessageFormat.format(ERROR_SAVE, file.getAbsolutePath()));
            LOG.error(e.getMessage(), e);
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_SAVE_HAR_FILE_ERROR);
        }
    }

    @Override
    public void performAction(HttpMessage httpMessage) {
        // Nothing to do, messages are handled as a whole.
    }

    private static byte[] packRequestInHarArchive(List<HttpMessage> httpMessages)
            throws IOException {
        HarLog harLog = HarUtils.createZapHarLog();
        HarEntries entries = new HarEntries();
        httpMessages.forEach(
                httpMessage -> {
                    if (httpMessage.getHistoryRef() == null) {
                        entries.addEntry(HarUtils.createHarEntry(httpMessage));
                    } else {
                        entries.addEntry(
                                HarUtils.createHarEntry(
                                        httpMessage.getHistoryRef().getHistoryId(),
                                        httpMessage.getHistoryRef().getHistoryType(),
                                        httpMessage));
                    }
                    Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_SAVE_HAR_FILE_MSG);
                });
        harLog.setEntries(entries);
        return HarUtils.harLogToByteArray(harLog);
    }

    private static File getOutputFile() {
        JFileChooser fileChooser = new EximFileChooser(HAR_FILE_EXTENSION, FILE_DESCRIPTION);
        int rc = fileChooser.showSaveDialog(View.getSingleton().getMainFrame());
        if (rc == JFileChooser.APPROVE_OPTION) {
            return fileChooser.getSelectedFile();
        }
        return null;
    }
}
