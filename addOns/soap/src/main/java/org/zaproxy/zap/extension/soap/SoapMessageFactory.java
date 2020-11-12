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
package org.zaproxy.zap.extension.soap;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import org.parosproxy.paros.network.HttpBody;

public class SoapMessageFactory {

    public static SOAPMessage createMessage(HttpBody messageBody)
            throws IOException, SOAPException {
        ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(SoapMessageFactory.class.getClassLoader());

            String content = messageBody.toString();
            if (content.contains(SOAPConstants.URI_NS_SOAP_1_1_ENVELOPE)) {
                return MessageFactory.newInstance(SOAPConstants.SOAP_1_1_PROTOCOL)
                        .createMessage(null, new ByteArrayInputStream(messageBody.getBytes()));
            } else if (content.contains(SOAPConstants.URI_NS_SOAP_1_2_ENVELOPE)) {
                return MessageFactory.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL)
                        .createMessage(null, new ByteArrayInputStream(messageBody.getBytes()));
            } else {
                return null;
            }
        } finally {
            Thread.currentThread().setContextClassLoader(oldClassLoader);
        }
    }
}
