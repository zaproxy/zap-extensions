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
package org.zaproxy.zap.extension.openapi;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.openapi.network.RequesterListener;

public class ImportPaneListener implements RequesterListener {

    private final ImportPane importPane;
    private int messagesSent = 0;
    private static final Logger LOG = LogManager.getLogger(ImportPaneListener.class);

    public ImportPaneListener(ImportPane importPane) {
        this.importPane = importPane;
    }

    @Override
    public void handleMessage(final HttpMessage message, int initiator) {
        if (!HttpStatusCode.isRedirection(message.getResponseHeader().getStatusCode())) {
            messagesSent++;
        }
        importPane.setImportStatus(Integer.toString(messagesSent));
        importPane.setCurrentImport(message.getRequestHeader().getURI().toString());
        importPane.updateProgBar(messagesSent);

        if (messagesSent == this.importPane.getTotalEndpoints()) {
            this.importPane.setProgressStatus(false);
        }
    }
}
