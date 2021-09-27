/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.commonlib;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/** A standard set of alert tags. */
public enum CommonAlertTag {
    // OWASP Top 10 2021
    OWASP_2021_A01_BROKEN_AC(
            "OWASP_2021_A01", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    OWASP_2021_A02_CRYPO_FAIL(
            "OWASP_2021_A02", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    OWASP_2021_A03_INJECTION("OWASP_2021_A03", "https://owasp.org/Top10/A03_2021-Injection/"),
    OWASP_2021_A04_INSECURE_DESIGN(
            "OWASP_2021_A04", "https://owasp.org/Top10/A04_2021-Insecure_Design/"),
    OWASP_2021_A05_SEC_MISCONFIG(
            "OWASP_2021_A05", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    OWASP_2021_A06_VULN_COMP(
            "OWASP_2021_A06",
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
    OWASP_2021_A07_AUTH_FAIL(
            "OWASP_2021_A07",
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
    OWASP_2021_A08_INTEGRITY_FAIL(
            "OWASP_2021_A08",
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"),
    OWASP_2021_A09_LOGGING_FAIL(
            "OWASP_2021_A09",
            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"),
    OWASP_2021_A10_SSRF(
            "OWASP_2021_A10",
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"),

    // OWASP Top 10 2017
    OWASP_2017_A01_INJECTION(
            "OWASP_2017_A01", "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html"),
    OWASP_2017_A02_BROKEN_AUTH(
            "OWASP_2017_A02",
            "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication.html"),
    OWASP_2017_A03_DATA_EXPOSED(
            "OWASP_2017_A03",
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html"),
    OWASP_2017_A04_XXE(
            "OWASP_2017_A04",
            "https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE).html"),
    OWASP_2017_A05_BROKEN_AC(
            "OWASP_2017_A05",
            "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control.html"),
    OWASP_2017_A06_SEC_MISCONFIG(
            "OWASP_2017_A06",
            "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html"),
    OWASP_2017_A07_XSS(
            "OWASP_2017_A07",
            "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS).html"),
    OWASP_2017_A08_INSECURE_DESERIAL(
            "OWASP_2017_A08",
            "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization.html"),
    OWASP_2017_A09_VULN_COMP(
            "OWASP_2017_A09",
            "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities.html"),
    OWASP_2017_A10_LOGGING_FAIL(
            "OWASP_2017_A10_LOGGING_FAIL",
            "https://owasp.org/www-project-top-ten/2017/A10_2017-Insufficient_Logging%2526Monitoring.html");

    private String tag;
    private String value;

    private CommonAlertTag(String tag, String value) {
        this.tag = tag;
        this.value = value;
    }

    public String getTag() {
        return this.tag;
    }

    public String getValue() {
        return value;
    }

    public static Map<String, String> toMap(CommonAlertTag... alertTags) {
        Map<String, String> map = new HashMap<>();
        for (CommonAlertTag tag : alertTags) {
            map.put(tag.getTag(), tag.getValue());
        }
        return Collections.unmodifiableMap(map);
    }
}
