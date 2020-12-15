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

import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

public class SoapAction {

    private final int wsdlId;
    private final String soapAction;

    public SoapAction(int wsdlId, String soapAction) {
        this.wsdlId = wsdlId;
        this.soapAction = soapAction;
    }

    public int getWsdlId() {
        return wsdlId;
    }

    public String getAction() {
        return soapAction;
    }

    /**
     * Extracts the SOAP action from the provided message.
     *
     * @param message the {@link HttpMessage SOAP message}
     * @return the extracted SOAP action, an empty string if the action has been omitted, or {@code
     *     null} if the provided message is not a valid SOAP message.
     */
    public static String extractFrom(HttpMessage message) {
        String soapAction = message.getRequestHeader().getHeader("SOAPAction");
        if (soapAction == null) {
            // Check if it is a SOAP v1.2 message. If it is, extract the SOAP action.
            String contentType = message.getRequestHeader().getHeader(HttpHeader.CONTENT_TYPE);
            if (contentType == null || !contentType.contains("application/soap+xml")) {
                // Not a SOAP message
                return null;
            }
            if (contentType.contains("action=")) {
                int soapActionBeginIndex = contentType.indexOf("action=") + "action=".length();
                int soapActionEndIndex = contentType.indexOf(';', soapActionBeginIndex);
                if (soapActionEndIndex == -1) {
                    soapActionEndIndex = contentType.length();
                }
                soapAction =
                        contentType
                                .substring(soapActionBeginIndex, soapActionEndIndex)
                                .replaceAll("\"", "");
            } else {
                soapAction = "";
            }
        }
        return soapAction;
    }
}
