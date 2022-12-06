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
package org.zaproxy.addon.reports.sarif;

/** Internal class to hold protocol and version separated. Also provides parse functionality. */
class SarifProtocolData {

    private String protocol;
    private String version;

    private SarifProtocolData() {}

    public static SarifProtocolData parseProtocolAndVersion(String versionString) {
        SarifProtocolData data = new SarifProtocolData();
        // assume it is something like HTTP/1.1 - so $protocol/$version
        if (versionString == null || versionString.length() < 3) {
            return data;
        }

        int slashIndex = versionString.indexOf('/');
        if (slashIndex < 1 || slashIndex == versionString.length() - 1) {
            return data;
        }
        data.protocol = versionString.substring(0, slashIndex);
        data.version = versionString.substring(slashIndex + 1);
        return data;
    }

    public String getVersion() {
        return version;
    }

    public String getProtocol() {
        return protocol;
    }
}
