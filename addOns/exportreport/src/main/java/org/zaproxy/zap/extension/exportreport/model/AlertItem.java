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

import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

@XmlType(name = "ExhibitionType", propOrder = { "pluginID", "alert", "riskCode", "confidence", "riskDesc", "desc", "solution", "otherInfo", "reference", "CWEID", "WASCID", "URI", "param", "attack", "evidence", "requestHeader", "requestBody", "responseHeader", "responseBody", "placeholder" })
public class AlertItem {
    private String pluginid;
    private String alert;
    private String riskcode;
    private String confidence;
    private String riskdesc;
    private String desc;
    private String solution;
    private String otherinfo;
    private String reference;
    private String cweid;
    private String wascid;

    private String uri;
    private String param;
    private String attack;
    private String evidence;

    private String requestheader;
    private String responseheader;
    private String requestbody;
    private String responsebody;

    List<String> placeholder;

    public String getAlert() {
        return alert;
    }

    @XmlElement(name = "Alert")
    public void setAlert(String alert) {
        this.alert = alert;
    }

    // ---------------------------------------------------------------
    public String getPluginID() {
        return pluginid;
    }

    @XmlElement(name = "PluginID")
    public void setPluginID(String pluginid) {
        this.pluginid = pluginid;
    }

    // ---------------------------------------------------------------
    public String getRiskCode() {
        return riskcode;
    }

    @XmlElement(name = "RiskCode")
    public void setRiskCode(String riskcode) {
        this.riskcode = riskcode;
    }

    // ---------------------------------------------------------------
    public String getConfidence() {
        return confidence;
    }

    @XmlElement(name = "Confidence")
    public void setConfidence(String confidence) {
        this.confidence = confidence;
    }

    // ---------------------------------------------------------------
    public String getRiskDesc() {
        return riskdesc;
    }

    @XmlElement(name = "RiskDesc")
    public void setRiskDesc(String riskdesc) {
        this.riskdesc = riskdesc;
    }
    // ---------------------------------------------------------------

    public String getDesc() {
        return desc;
    }

    @XmlElement(name = "Desc")
    public void setDesc(String desc) {
        this.desc = desc;
    }

    // ---------------------------------------------------------------

    public String getSolution() {
        return solution;
    }

    @XmlElement(name = "Solution")
    public void setSolution(String solution) {
        this.solution = solution;
    }
    // ---------------------------------------------------------------

    public String getOtherInfo() {
        return otherinfo;
    }

    @XmlElement(name = "OtherInfo")
    public void setOtherInfo(String otherinfo) {
        this.otherinfo = otherinfo;
    }
    // ---------------------------------------------------------------

    public String getReference() {
        return reference;
    }

    @XmlElement(name = "Reference")
    public void setReference(String reference) {
        this.reference = reference;
    }
    // ---------------------------------------------------------------

    public String getCWEID() {
        return cweid;
    }

    @XmlElement(name = "CWEID")
    public void setCWEID(String cweid) {
        this.cweid = cweid;
    }
    // ---------------------------------------------------------------

    public String getWASCID() {
        return wascid;
    }

    @XmlElement(name = "WASCID")
    public void setWASCID(String wascid) {
        this.wascid = wascid;
    }
    // ---------------------------------------------------------------

    public String getURI() {
        return uri;
    }

    @XmlElement(name = "URI")
    public void setURI(String uri) {
        this.uri = uri;
    }
    // ---------------------------------------------------------------

    public String getParam() {
        return param;
    }

    @XmlElement(name = "Param")
    public void setParam(String param) {
        this.param = param;
    }

    // ---------------------------------------------------------------

    public String getAttack() {
        return attack;
    }

    @XmlElement(name = "Attack")
    public void setAttack(String attack) {
        this.attack = attack;
    }

    // ---------------------------------------------------------------

    public String getEvidence() {
        return evidence;
    }

    @XmlElement(name = "Evidence")
    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    // ---------------------------------------------------------------

    public String getRequestHeader() {
        return requestheader;
    }

    @XmlElement(name = "RequestHeader")
    public void setRequestHeader(String requestheader) {
        this.requestheader = requestheader;
    }

    // ---------------------------------------------------------------

    public String getRequestBody() {
        return requestbody;
    }

    @XmlElement(name = "RequestBody")
    public void setRequestBody(String requestbody) {
        this.requestbody = requestbody;
    }

    // ---------------------------------------------------------------

    public String getResponseHeader() {
        return responseheader;
    }

    @XmlElement(name = "ResponseHeader")
    public void setResponseHeader(String responseheader) {
        this.responseheader = responseheader;
    }

    // ---------------------------------------------------------------

    public String getResponseBody() {
        return responsebody;
    }

    @XmlElement(name = "ResponseBody")
    public void setResponseBody(String responsebody) {
        this.responsebody = responsebody;
    }

    // ---------------------------------------------------------------

    public List<String> getPlaceholder() {
        return placeholder;
    }

    @XmlElement(name = "Placeholder")
    public void setPlaceholder(List<String> placeholder) {
        this.placeholder = placeholder;
    }
    // ---------------------------------------------------------------
}