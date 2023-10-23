/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.dns;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dns.exceptions.TooManyRecordsException;

public class SpfScanRule extends AbstractHostPlugin {
    private static final int ID = 90040;
    private static final Logger LOGGER = LogManager.getLogger(SpfScanRule.class);
    private static final String MESSAGE_PREFIX = "dns.spf.";
    private static List<String> reviewedDomains = Collections.synchronizedList(new ArrayList<>());

    private static String getConstantString(String key) {
        return Constant.messages.getString(MESSAGE_PREFIX + key);
    }

    private String getHigherSubdomain(String host) {
        String[] hostarray = host.split("\\.");
        if (hostarray.length < 2) {
            return null;
        }
        return String.join(".", Arrays.copyOfRange(hostarray, 1, hostarray.length));
    }

    @Override
    public void scan() {
        final HttpMessage originalMsg = getBaseMsg();
        try {
            String host = originalMsg.getRequestHeader().getURI().getHost();
            DnsClient dns = new DnsClient();
            SpfParser spf = findValidSpfRecord(host, dns);
            if (spf == null) {
                newAlert()
                        .setMessage(getBaseMsg())
                        .setRisk(Alert.RISK_INFO)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setDescription(getConstantString("norecord.description"))
                        .raise();
            }
        } catch (URIException e) {
            LOGGER.debug("There was a problem getting the TXT records: ", e);
        } catch (TooManyRecordsException e) {
            newAlert()
                    .setMessage(getBaseMsg())
                    .setRisk(Alert.RISK_INFO)
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setDescription(getConstantString("toomanyrecords.description"))
                    .raise();
        }
    }

    private SpfParser findValidSpfRecord(String host, DnsClient dns)
            throws TooManyRecordsException {
        SpfParser spf = null;
        while (host != null) {
            if (hasBeenAlreadyAnalyzed(host)) {
                return null;
            }
            markAsAnalyzed(host);
            spf = new SpfParser(dns.getTxtRecord(host));
            if (spf.hasSpfRecord()) {
                break;
            }
            host = getHigherSubdomain(host);
        }
        return spf;
    }

    private void markAsAnalyzed(String host) {
        reviewedDomains.add(host);
    }

    private boolean hasBeenAlreadyAnalyzed(String host) {
        return reviewedDomains.contains(host);
    }

    @Override
    public int getId() {
        return ID;
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getName() {
        return getConstantString("name");
    }

    @Override
    public String getDescription() {
        return getConstantString("description");
    }

    @Override
    public String getSolution() {
        return "";
    }

    @Override
    public String getReference() {
        return "";
    }
}
