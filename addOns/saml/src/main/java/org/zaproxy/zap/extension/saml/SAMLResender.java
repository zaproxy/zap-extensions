/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.saml;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;

public class SAMLResender {

    private static Logger log = LogManager.getLogger(SAMLResender.class);

    private SAMLResender() {}

    /**
     * Resend the message to the desired endpoint and get the response
     *
     * @param msg The message to be sent
     */
    public static void resendMessage(final HttpMessage msg) throws SAMLException {
        HttpSender sender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(),
                        true,
                        HttpSender.MANUAL_REQUEST_INITIATOR);
        try {
            sender.sendAndReceive(msg, true);
            if (!msg.getResponseHeader().isEmpty()) {
                final ExtensionHistory extension =
                        (ExtensionHistory)
                                Control.getSingleton()
                                        .getExtensionLoader()
                                        .getExtension(ExtensionHistory.NAME);

                final int finalType = HistoryReference.TYPE_ZAP_USER;
                extension.addHistory(msg, finalType);
            }

        } catch (IOException e) {
            log.error(e.getMessage());
            throw new SAMLException("Message sending failed", e);
        }
    }
}
