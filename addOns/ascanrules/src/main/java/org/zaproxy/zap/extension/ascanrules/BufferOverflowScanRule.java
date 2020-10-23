/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
/*
 * Buffer Overflow an active scan rule
 * Copyright (C) 2015 Institute for Defense Analyses
 * @author Mark Rader based upon the example active scanner by psiinon
 */
package org.zaproxy.zap.extension.ascanrules;

import java.io.IOException;
import java.net.UnknownHostException;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

public class BufferOverflowScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.bufferoverflow.";

    private static final int PLUGIN_ID = 30001;
    private static Logger log = Logger.getLogger(BufferOverflowScanRule.class);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.C);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    public String getOther() {
        return Constant.messages.getString(MESSAGE_PREFIX + "other");
    }

    /*
     * This method is called by the active scanner for each GET and POST parameter for every page
     * @see org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.paros.network.HttpMessage, java.lang.String, java.lang.String)
     */
    @Override
    public void scan(HttpMessage msg, String param, String value) {

        if (this.isStop()) { // Check if the user stopped things
            if (log.isDebugEnabled()) {
                log.debug("Scanner " + this.getName() + " Stopping.");
            }
            return; // Stop!
        }
        if (getBaseMsg().getResponseHeader().getStatusCode()
                == HttpStatusCode
                        .INTERNAL_SERVER_ERROR) // Check to see if the page closed initially
        {
            return; // Stop
        }

        try {
            // This is where you change the 'good' request to attack the application
            // You can make multiple requests if needed
            String checkStringHeader1 = "Connection: close"; // Un natural close
            String returnAttack = randomCharacterString(2100);
            setParameter(msg, param, returnAttack);
            try {
                sendAndReceive(msg);
            } catch (UnknownHostException ex) {
                if (log.isDebugEnabled())
                    log.debug(
                            "Caught "
                                    + ex.getClass().getName()
                                    + " "
                                    + ex.getMessage()
                                    + " when accessing: "
                                    + msg.getRequestHeader().getURI().toString()
                                    + "\n The target may have replied with a poorly formed redirect due to our input.");
                return; // Something went wrong no point continuing
            }

            HttpResponseHeader requestReturn = msg.getResponseHeader();
            // This is where BASE baseResponseBody was you detect potential vulnerabilities in the
            // response
            String chkerrorheader = requestReturn.getHeadersAsString();
            log.debug("Header: " + chkerrorheader);
            if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.INTERNAL_SERVER_ERROR
                    && chkerrorheader.contains(checkStringHeader1)) {
                log.debug("Found Header");
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setUri(this.getBaseMsg().getRequestHeader().getURI().toString())
                        .setParam(param)
                        .setEvidence(msg.getRequestHeader().toString())
                        .setOtherInfo(getOther())
                        .setMessage(msg)
                        .raise();
                return;
            }

            return;
        } catch (URIException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to send HTTP message, cause: " + e.getMessage());
            }
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        // The CWE id
        return 120;
    }

    @Override
    public int getWascId() {
        // The WASC ID
        return 7;
    }

    private String randomCharacterString(int length) {
        StringBuilder sb1 = new StringBuilder(length + 1);
        int counter = 0;
        int character = 0;
        while (counter < length) {
            character = 65 + (int) (Math.random() * 57);

            while (character > 90 && character < 97) {
                character = 65 + (int) (Math.random() * 57);
            }

            counter = counter + 1;
            sb1.append((char) character);
        }
        return sb1.toString();
    }
}
