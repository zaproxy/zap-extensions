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
package org.zaproxy.addon.graphql;

import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.utils.ThreadUtils;

public class HistoryPersister implements RequesterListener {

    private static final Logger LOG = Logger.getLogger(ExtensionGraphQl.class);

    @Override
    public void handleMessage(final HttpMessage message, int initiator) {
        // Add the message to the history panel and sites tree
        final HistoryReference historyRef;

        try {
            historyRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(),
                            initiator == HttpSender.SPIDER_INITIATOR
                                    ? HistoryReference.TYPE_SPIDER
                                    : HistoryReference.TYPE_ZAP_USER,
                            message);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            return;
        }

        final ExtensionHistory extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        try {
            ThreadUtils.invokeAndWait(
                    () -> {
                        extHistory.addHistory(historyRef);
                        Model.getSingleton()
                                .getSession()
                                .getSiteTree()
                                .addPath(historyRef, message);
                    });
        } catch (Exception e) {
            LOG.error("Could not add message to sites tree.", e);
            return;
        }
    }
}
