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

import java.io.IOException;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.w3c.dom.NodeList;

public class SitesTreeHelper {

    private static final Logger LOG = Logger.getLogger(ExtensionImportWSDL.class);

    /**
     * Returns a node name based on the SOAP version and the operation name in the provided message.
     * If the SOAP message is malformed, an empty string is returned.
     *
     * @param message The message for which a node name is required.
     */
    public static String getNodeName(HttpMessage message) {
        try {
            SOAPMessage soapMsg = SoapMessageFactory.createMessage(message.getRequestBody());
            if (soapMsg == null) {
                return "";
            }
            NodeList nodeList = soapMsg.getSOAPBody().getChildNodes();
            StringBuilder leafName = new StringBuilder();
            for (int i = 0; i < nodeList.getLength(); i++) {
                if (nodeList.item(i).getLocalName() != null) {
                    leafName.append(nodeList.item(i).getLocalName()).append(", ");
                }
            }
            // Remove the extra ", " at the end.
            leafName.setLength(leafName.length() - 2);
            // Append SOAP Version.
            leafName.append(
                    message.getRequestHeader().getHeader("SOAPAction") == null
                            ? " (v1.2)"
                            : " (v1.1)");
            return leafName.toString();
        } catch (SOAPException | IOException e) {
            LOG.warn("Malformed SOAP Message.");
            return "";
        }
    }
}
