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
package org.zaproxy.addon.exim.har;

import edu.umass.cs.benchlab.har.tools.HarFileReader;
import java.awt.EventQueue;
import java.io.File;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;

final class HarImportUtil {

    private static final Logger LOG = LogManager.getLogger(HarImportUtil.class);

    static void importHarFile(File file) {
        try {
            processMessages(file);
        } catch (IOException e) {
            LOG.error(e);
            View.getSingleton()
                    .showWarningDialog(
                            Constant.messages.getString(
                                    "exim.har.file.import.error", file.getAbsolutePath()));
        }
    }

    public static void processMessages(File file) throws IOException {
        List<HttpMessage> messages =
                HarImporter.getHttpMessages(new HarFileReader().readHarFile(file));
        messages.forEach(message -> persistMessage(message));
    }

    private static void persistMessage(final HttpMessage message) {
        // Add the message to the history panel and sites tree
        final HistoryReference historyRef;

        if (message.getHistoryRef() == null) {
            try {
                historyRef =
                        new HistoryReference(
                                Model.getSingleton().getSession(),
                                HistoryReference.TYPE_ZAP_USER,
                                message);
            } catch (Exception e) {
                LOG.warn(e.getMessage(), e);
                return;
            }
        } else {
            historyRef = message.getHistoryRef();
        }

        final ExtensionHistory extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        if (extHistory != null) {
            EventQueue.invokeLater(
                    new Runnable() {
                        @Override
                        public void run() {
                            extHistory.addHistory(historyRef);
                            Model.getSingleton()
                                    .getSession()
                                    .getSiteTree()
                                    .addPath(historyRef, message);
                        }
                    });
        }
    }
}
