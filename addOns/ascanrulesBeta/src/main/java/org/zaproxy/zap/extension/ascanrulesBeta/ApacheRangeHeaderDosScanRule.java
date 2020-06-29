/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Active scan rule which checks whether or not the server is subject to the Apache Range Header
 * Denial of Service vulnerability: CVE-2011-3192. Based loosely on:
 * https://github.com/alienwithin/php-utilities/blob/master/apache-byte-range-
 * server-dos/apache_byte_range_server_dos.php
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class ApacheRangeHeaderDosScanRule extends AbstractAppPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanbeta.apacherangeheaderdos.";

    private static final int PLUGIN_ID = 10053;

    private static final Logger LOG = Logger.getLogger(ApacheRangeHeaderDosScanRule.class);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.Apache);
    }

    @Override
    public int getCategory() {
        return Category.SERVER;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        return 400; // CWE-400: Uncontrolled Resource Consumption
    }

    @Override
    public int getWascId() {
        return 10; // WASC-10: Denial of Service
    }

    @Override
    public void scan() {

        // Check if the user stopped things. One request per URL so check before
        // sending the request
        if (isStop()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Scan rule " + getName() + " Stopping.");
            }
            return;
        }

        if (acceptsRangeRequests()) { // Server handles ranges
            HttpMessage newRequest = getNewMsg();
            setRequestHeaders(newRequest, "3-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9,10-10,11-11");
            // Send a request for 11 ranges, 1 more than permitted
            try {
                sendAndReceive(newRequest, false);
            } catch (IOException e) {
                LOG.warn(
                        "An error occurred while checking ["
                                + newRequest.getRequestHeader().getMethod()
                                + "] ["
                                + newRequest.getRequestHeader().getURI()
                                + "] for Apache Range Header DoS (CVE-2011-3192)."
                                + "Caught "
                                + e.getClass().getName()
                                + " "
                                + e.getMessage());
                return;
            }

            if (newRequest.getResponseHeader().getStatusCode() == HttpStatusCode.PARTIAL_CONTENT) {
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setEvidence(newRequest.getResponseHeader().getPrimeHeader())
                        .setMessage(newRequest)
                        .raise();
            }
        }
    }

    private boolean acceptsRangeRequests() {
        HttpMessage chkRequest = getNewMsg();
        setRequestHeaders(chkRequest, "0-6");

        try {
            sendAndReceive(chkRequest, false);
        } catch (IOException e) {
            LOG.warn(
                    "An error occurred while validating ["
                            + chkRequest.getRequestHeader().getMethod()
                            + "] ["
                            + chkRequest.getRequestHeader().getURI()
                            + "] for Apache Range Header DoS (CVE-2011-3192) applicability."
                            + "Caught "
                            + e.getClass().getName()
                            + " "
                            + e.getMessage());
            return false;
        }

        return chkRequest.getResponseHeader().getStatusCode() == HttpStatusCode.PARTIAL_CONTENT;
    }

    private void setRequestHeaders(HttpMessage aMessage, String rangeValue) {
        rangeValue = "bytes=" + rangeValue;
        aMessage.getRequestHeader().setHeader("Range", rangeValue);
        aMessage.getRequestHeader().setHeader("Request-Range", rangeValue);
        aMessage.getRequestHeader().setHeader("Connection", "close");
    }
}
