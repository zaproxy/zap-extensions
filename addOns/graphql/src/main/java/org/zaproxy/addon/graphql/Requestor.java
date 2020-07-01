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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.network.HttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestConfig;

public class Requestor {

    private final int initiator;
    private List<RequesterListener> listeners = new ArrayList<RequesterListener>();
    private HttpSender sender;
    private final HttpRequestConfig requestConfig;
    private static final Logger LOG = Logger.getLogger(Requestor.class);

    public Requestor(int initiator) {
        this.initiator = initiator;
        sender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(),
                        true,
                        initiator);
        requestConfig =
                HttpRequestConfig.builder().setRedirectionValidator(new MessageHandler()).build();
    }

    public void send(HttpMessage message) {
        try {
            sender.sendAndReceive(message, requestConfig);
        } catch (IOException e) {
            LOG.error(e.getMessage(), e);
        }
    }

    public void addListener(RequesterListener listener) {
        this.listeners.add(listener);
    }

    public void removeListener(RequesterListener listener) {
        this.listeners.remove(listener);
    }

    /** Notifies the {@link #listeners} of the messages sent. */
    private class MessageHandler implements HttpRedirectionValidator {

        @Override
        public void notifyMessageReceived(HttpMessage message) {
            for (RequesterListener listener : listeners) {
                try {
                    listener.handleMessage(message, initiator);
                } catch (Exception e) {
                    LOG.error(e.getMessage(), e);
                }
            }
        }

        @Override
        public boolean isValid(URI redirection) {
            return true;
        }
    }
}
