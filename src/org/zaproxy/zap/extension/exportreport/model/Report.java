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
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

@XmlType(name = "", propOrder = { "title", "by", "for", "scanDate", "scanVersion", "reportDate", "reportVersion", "desc", "sites" })
@XmlRootElement(name = "Report")
public class Report {
    String title;
    String reportBy;
    String reportFor;
    String scanDate;
    String scanVersion;
    String reportDate;
    String reportVersion;
    String desc;
    List<Sites> sites;

    public String getTitle() {
        return title;
    }

    @XmlElement(name = "Title")
    public void setTitle(String title) {
        this.title = title;
    }

    public String getBy() {
        return reportBy;
    }

    @XmlElement(name = "By")
    public void setBy(String reportBy) {
        this.reportBy = reportBy;
    }

    public String getFor() {
        return reportFor;
    }

    @XmlElement(name = "For")
    public void setFor(String reportFor) {
        this.reportFor = reportFor;
    }

    public String getScanDate() {
        return scanDate;
    }

    @XmlElement(name = "ScanDate")
    public void setScanDate(String scanDate) {
        this.scanDate = scanDate;
    }

    public String getScanVersion() {
        return scanVersion;
    }

    @XmlElement(name = "ScanVersion")
    public void setScanVersion(String scanVersion) {
        this.scanVersion = scanVersion;
    }

    public String getReportDate() {
        return reportDate;
    }

    @XmlElement(name = "ReportDate")
    public void setReportDate(String reportDate) {
        this.reportDate = reportDate;
    }

    public String getReportVersion() {
        return reportVersion;
    }

    @XmlElement(name = "ReportVersion")
    public void setReportVersion(String reportVersion) {
        this.reportVersion = reportVersion;
    }

    public String getDesc() {
        return desc;
    }

    @XmlElement(name = "Desc")
    public void setDesc(String desc) {
        this.desc = desc;
    }

    public List<Sites> getSites() {
        return sites;
    }

    @XmlElement(name = "Sites")
    public void setSites(List<Sites> sites) {
        this.sites = sites;
    }

    public void add(Sites sites) {
        if (this.sites == null) {
            this.sites = new ArrayList<Sites>();
        }
        this.sites.add(sites);

    }

}
