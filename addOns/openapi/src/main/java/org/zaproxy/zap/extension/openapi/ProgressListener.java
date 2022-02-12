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
package org.zaproxy.zap.extension.openapi;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.ui.ProgressPane;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.zap.extension.openapi.network.RequesterListener;

public class ProgressListener extends ProgressPaneListener implements RequesterListener {

    public ProgressListener(ProgressPane progressPane) {
        super(progressPane);
    }

    @Override
    public void handleMessage(final HttpMessage message, int initiator) {
        if (!HttpStatusCode.isRedirection(message.getResponseHeader().getStatusCode())) {
            setTasksDone(getTasksDone() + 1);
        }
        getProgressPane().setProcessedTasks(getTasksDone());
        getProgressPane()
                .setCurrentTask(
                        Constant.messages.getString(
                                "openapi.progress.importpane.currentimport",
                                message.getRequestHeader().getURI().toString()));
    }
}
