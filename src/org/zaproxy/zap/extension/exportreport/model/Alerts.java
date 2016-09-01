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

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

@XmlType(name = "AlertsType", propOrder = { "alertItem", "temp", "placeholder" })
public class Alerts {

    List<AlertItem> alertItem;

    private String temp;
    Placeholder placeholder;

    public List<AlertItem> getAlertItem() {
        return alertItem;
    }

    @XmlElement(name = "AlertItem")
    public void setAlertItem(List<AlertItem> alertItem) {
        this.alertItem = alertItem;
    }

    public void add(AlertItem alertItem) {
        if (this.alertItem == null) {
            this.alertItem = new ArrayList<AlertItem>();
        }
        this.alertItem.add(alertItem);

    }

    public String getTemp() {
        return temp;
    }

    @XmlElement(name = "Temp")
    public void setTemp(String temp) {
        this.temp = temp;
    }

    public Placeholder getPlaceholder() {
        return placeholder;
    }

    @XmlElement(name = "Placeholder")
    public void setPlaceholder(Placeholder placeholder) {
        this.placeholder = placeholder;
    }
}
