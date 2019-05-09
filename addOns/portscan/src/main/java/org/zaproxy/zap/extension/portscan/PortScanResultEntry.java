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
package org.zaproxy.zap.extension.portscan;

import org.parosproxy.paros.Constant;

public class PortScanResultEntry {

    private final Integer port;
    private final String description;

    public PortScanResultEntry(int port) {
        this.port = Integer.valueOf(port);

        String messagesKey = "ports.port." + port;

        String portDesc;
        if (Constant.messages.containsKey(messagesKey)) {
            portDesc = Constant.messages.getString(messagesKey);
        } else {
            portDesc = Constant.messages.getString("ports.port.unknown");
        }
        description = portDesc;
    }

    public Integer getPort() {
        return port;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public int hashCode() {
        return 31 + ((port == null) ? 0 : port.hashCode());
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null) {
            return false;
        }
        if (getClass() != object.getClass()) {
            return false;
        }
        PortScanResultEntry other = (PortScanResultEntry) object;
        if (port == null) {
            if (other.port != null) {
                return false;
            }
        } else if (!port.equals(other.port)) {
            return false;
        }
        return true;
    }
}
