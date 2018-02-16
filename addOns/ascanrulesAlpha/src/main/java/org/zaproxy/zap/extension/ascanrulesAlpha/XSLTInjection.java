/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * The XSLTInjection plugin identifies XSLT injection vulnerabilities with all the parameters in GET
 * and POST
 *
 * @author CaptainFreak
 */
public class XSLTInjection extends AbstractAppParamPlugin {

    private static final Logger LOG = Logger.getLogger(XSLTInjection.class);

    private static final String[] errorCausingPayloads = {"<", ">", "\'", "\""};

    private static final String[] vendorReturningPayloads = {
        "<xsl:value-of select=\"system-property(\'xsl:vendor\')\"/>",
        "system-property(\'xsl:vendor\')/>",
        "\"/><xsl:value-of select=\"system-property(\'xsl:vendor\')\"/><!--",
        "<xsl:value-of select=\"system-property(\'xsl:vendor\')\"/><!--"
    };
    private static final String[] xsltVendors = {
        "libxslt", "Microsoft", "Saxonica", "Apache", "Xalan", "SAXON", "Transformiix"
    };

    // TODO Add time based payloads (SSRF) and improve accuracy

    @Override
    public int getId() {
        return 90017;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanalpha.xsltinjection.xslt.name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.XML);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanalpha.xsltinjection.xslt.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanalpha.xsltinjection.xslt.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanalpha.xsltinjection.xslt.refs");
    }

    @Override
    public void init() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Initialising XSLT Scanner.");
        }
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        if (!messageContainsVendor(msg)) {
            try {
                // Count positive Tests
                boolean positiveBasedOnError = false;
                // error causing tests
                for (String payload : errorCausingPayloads) {
                    msg = getNewMsg();
                    setParameter(msg, param, payload);
                    sendAndReceive(msg);
                    if (!msg.getResponseBody().toString().contains(payload)) {
                        positiveBasedOnError = true;
                        break;
                    }
                    // Stop the testing if user requests
                    if (isStop()) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Stopping the scan due to a user request");
                        }
                        return;
                    }
                }
                // vendor returning tests
                if (positiveBasedOnError == true) {
                    for (String payload : vendorReturningPayloads) {
                        msg = getNewMsg();
                        setParameter(msg, param, payload);
                        sendAndReceive(msg);
                        for (String vendor : xsltVendors) {
                            if (msg.getResponseBody().toString().contains(vendor)) {
                                // We found the injection point
                                bingo(
                                        Alert.RISK_HIGH,
                                        Alert.CONFIDENCE_MEDIUM,
                                        getName(),
                                        getDescription(),
                                        getBaseMsg().getRequestHeader().getURI().toString(),
                                        param,
                                        payload,
                                        "",
                                        getSolution(),
                                        vendor,
                                        msg);

                                return;
                            }
                            // Stop the testing if user requests
                            if (isStop()) {
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("Stopping the scan due to a user request");
                                }
                                return;
                            }
                        }
                    }
                }
            } catch (IOException e) {
                LOG.error(e.getMessage(), e);
            }
        }
    }

    private boolean messageContainsVendor(HttpMessage msg) {
        for (String vendor : xsltVendors) {
            if (msg.getResponseBody().toString().contains(vendor)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 91;
    }

    @Override
    public int getWascId() {
        return 23;
    }
}
