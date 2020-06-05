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

import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.utils.ThreadUtils;

public class GraphQlParser {

    private static final Logger LOG = Logger.getLogger(GraphQlParser.class);

    public static void parse(URI uri) {
        HttpMessage msg;
        try {
            msg = new HttpMessage(uri);
            HttpSender sender =
                    new HttpSender(
                            Model.getSingleton().getOptionsParam().getConnectionParam(),
                            true,
                            HttpSender.MANUAL_REQUEST_INITIATOR);
            sender.sendAndReceive(msg, true);
        } catch (Exception e) {
            LOG.error("Unable to send request.", e);
            return;
        }

        // Add the message to the history panel and sites tree
        ExtensionHistory extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        try {
            ThreadUtils.invokeAndWait(
                    () -> {
                        extHistory.addHistory(msg, HistoryReference.TYPE_ZAP_USER);
                        Model.getSingleton()
                                .getSession()
                                .getSiteTree()
                                .addPath(msg.getHistoryRef(), msg);
                    });
        } catch (Exception e) {
            LOG.error("Could not add message to sites tree.", e);
        }
    }
}
