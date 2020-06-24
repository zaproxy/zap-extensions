/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesBeta;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A class to passively scan responses for HTTP header signatures that indicate that the web server
 * is vulnerable to the HeartBleed OpenSSL vulnerability
 *
 * @author 70pointer@gmail.com
 */
public class HeartBleedScanRule extends PluginPassiveScanner {

    /**
     * a pattern to identify the version reported in the header. This works for Apache2 (subject to
     * the reported version containing back-ported security fixes). There is no equivalent way to
     * check Nginx, so don't even try. The only way to be absolutely sure is to exploit it :)
     */
    private static Pattern openSSLversionPattern =
            Pattern.compile("Server:.*?(OpenSSL/([0-9.]+[a-z-0-9]+))", Pattern.CASE_INSENSITIVE);

    /**
     * vulnerable versions, courtesy of
     * http://cvedetails.com/cve-details.php?t=1&cve_id=CVE-2014-0160
     */
    static String[] openSSLvulnerableVersions = {
        "1.0.1-Beta1",
        "1.0.1-Beta2",
        "1.0.1-Beta3",
        "1.0.1",
        "1.0.1a",
        "1.0.1b",
        "1.0.1c",
        "1.0.1d",
        "1.0.1e",
        "1.0.1f",
        "1.0.2-beta" // does not come from the page above, but reported elsewhere to be vulnerable.
    };

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanbeta.heartbleed.";

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // do nothing
    }

    /**
     * scans the HTTP response for signatures that might indicate the Heartbleed OpenSSL
     * vulnerability
     *
     * @param msg
     * @param id
     * @param source unused
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        // get the body contents as a String, so we can match against it
        String responseHeaders = msg.getResponseHeader().getHeadersAsString();

        Matcher matcher = openSSLversionPattern.matcher(responseHeaders);
        while (matcher.find()) {
            String fullVersionString = matcher.group(1); // get the full string e.g. OpenSSL/1.0.1e
            String versionNumber = matcher.group(2); // get the version e.g. 1.0.1e

            // if the version matches any of the known vulnerable versions, raise an alert.
            for (String openSSLvulnerableVersion : openSSLvulnerableVersions) {
                if (versionNumber.equalsIgnoreCase(openSSLvulnerableVersion)) {
                    raiseAlert(msg, id, fullVersionString);
                    return;
                }
            }
        }
    }

    private void raiseAlert(HttpMessage msg, int id, String fullVersionString) {
        // Suspicious, but not a warning, because the reported version could have a
        // security back-port.
        newAlert()
                .setRisk(Alert.RISK_HIGH)
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(getDescription())
                .setOtherInfo(getExtraInfo(fullVersionString))
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(fullVersionString)
                .setCweId(119) // CWE 119: Failure to Constrain Operations within the Bounds of a
                // Memory Buffer
                .setWascId(20) // WASC-20: Improper Input Handling
                .raise();
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public int getPluginId() {
        return 10034;
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    private String getExtraInfo(String opensslVersion) {
        return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", opensslVersion);
    }
}
