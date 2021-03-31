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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.network.HttpMessage;

public class SAMLProxyListener implements ProxyListener {

    private SAMLConfiguration configuration;

    protected static final Logger log = LogManager.getLogger(SAMLProxyListener.class);

    public SAMLProxyListener() {
        configuration = SAMLConfiguration.getInstance();
    }

    /**
     * Check whether the passive listener is activated. If deactivated the requests will be
     * unchanged even the attributes to be changed, exists in the message
     */
    public boolean isActive() {
        return configuration.getAutoChangeEnabled();
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage message) {
        if (isActive() && SAMLUtils.hasSAMLMessage(message)) {
            try {
                SAMLMessage samlMessage = new SAMLMessage(message);

                // change the params
                for (Attribute attribute : configuration.getAutoChangeAttributes()) {
                    String value = attribute.getValue().toString();
                    boolean changed =
                            samlMessage.changeAttributeValueTo(attribute.getName(), value);
                    if (changed) {
                        log.debug("{}: value changed to {}", attribute.getName(), value);
                    }
                }

                // change the original message
                HttpMessage changedMessege = samlMessage.getChangedMessage();
                if (changedMessege != message) {
                    // check for reference, if they are same the message is already changed,
                    // else the header and body are changed
                    message.setRequestBody(changedMessege.getRequestBody());
                    message.setRequestHeader(changedMessege.getRequestHeader());
                }

            } catch (SAMLException ignored) {
            }
        }
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage message) {
        return true;
    }

    @Override
    public int getArrangeableListenerOrder() {
        return 0;
    }
}
