/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * This file is based on the Paros code file ReportLastScan.java
 */
package org.zaproxy.zap.extension.exportreport.model;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

@XmlType(name = "SitesType", propOrder = { "host", "name", "port", "SSL", "alerts" })
public class Sites {
    private String host;
    private String name;
    private String port;
    private String ssl;
    private Alerts alerts;

    public Alerts getAlerts() {
        return alerts;
    }

    @XmlElement(name = "Alerts")
    public void setAlerts(Alerts alerts) {
        this.alerts = alerts;
    }

    public String getHost() {
        return host;
    }

    @XmlElement(name = "Host")
    public void setHost(String host) {
        this.host = host;
    }

    public String getName() {
        return name;
    }

    @XmlElement(name = "Name")
    public void setName(String name) {
        this.name = name;
    }

    public String getPort() {
        return port;
    }

    @XmlElement(name = "Port")
    public void setPort(String port) {
        this.port = port;
    }

    public String getSSL() {
        return ssl;
    }

    @XmlElement(name = "SSL")
    public void setSSL(String ssl) {
        this.ssl = ssl;
    }
}
