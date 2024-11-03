/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.oast.internal;

import java.sql.Timestamp;
import javax.jdo.annotations.Cacheable;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import org.datanucleus.api.jdo.annotations.CreateTimestamp;
import org.parosproxy.paros.core.scanner.Alert;

@Cacheable("false")
@PersistenceCapable(table = "ALERT", detachable = "true")
public class AlertEntity {

    @CreateTimestamp private Timestamp createTimestamp;

    @PrimaryKey
    @Column(length = 512)
    @Index(name = "ALERT_PAYLOAD_IDX")
    @Persistent(valueStrategy = IdGeneratorStrategy.IDENTITY)
    private Integer id;

    private String payload;

    @Column(name = "MESSAGEID")
    @Persistent(dependent = "true")
    private MessageEntity message;

    private int alertId;
    private int pluginId;

    @Column(length = 16777216)
    private String name;

    private int risk;
    private int confidence;

    @Column(length = 16777216)
    private String description;

    @Column(length = 1048576)
    private String uri;

    @Column(length = 16777216)
    private String param;

    @Column(length = 32768)
    private String attack;

    @Column(length = 16777216)
    private String otherInfo;

    @Column(length = 16777216)
    private String solution;

    @Column(length = 16777216)
    private String reference;

    @Column(length = 16777216)
    private String evidence;

    @Column(length = 256)
    private String inputVector;

    private int cweId;
    private int wascId;
    private int sourceId;

    @Column(length = 256)
    private String alertRef;

    public AlertEntity(String payload, MessageEntity message, Alert alert) {
        this.payload = payload;
        this.message = message;

        alertId = alert.getAlertId();
        pluginId = alert.getPluginId();
        name = alert.getName();
        risk = alert.getRisk();
        confidence = alert.getConfidence();
        description = alert.getDescription();
        uri = alert.getUri();
        param = alert.getParam();
        attack = alert.getAttack();
        otherInfo = alert.getOtherInfo();
        solution = alert.getSolution();
        reference = alert.getReference();
        evidence = alert.getEvidence();
        inputVector = alert.getInputVector();
        cweId = alert.getCweId();
        wascId = alert.getWascId();
        sourceId = alert.getSource() == null ? 0 : alert.getSource().getId();
        alertRef = alert.getAlertRef();
    }

    public Alert toAlert() throws Exception {
        var alert = new Alert(pluginId);
        alert.setAlertId(alertId);
        alert.setName(name);
        alert.setRisk(risk);
        alert.setConfidence(confidence);
        alert.setDescription(description);
        alert.setUri(uri);
        alert.setParam(param);
        alert.setAttack(attack);
        alert.setOtherInfo(otherInfo);
        alert.setSolution(solution);
        alert.setReference(reference);
        alert.setEvidence(evidence);
        alert.setInputVector(inputVector);
        alert.setCweId(cweId);
        alert.setWascId(wascId);
        alert.setSource(Alert.Source.getSource(sourceId));
        alert.setAlertRef(alertRef);
        alert.setMessage(message.toHttpMessage());
        return alert;
    }

    public Timestamp getCreateTimestamp() {
        return createTimestamp;
    }

    public void setCreateTimestamp(Timestamp createTimestamp) {
        this.createTimestamp = createTimestamp;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public MessageEntity getMessage() {
        return message;
    }

    public void setMessage(MessageEntity message) {
        this.message = message;
    }

    public int getAlertId() {
        return alertId;
    }

    public void setAlertId(int alertId) {
        this.alertId = alertId;
    }

    public int getPluginId() {
        return pluginId;
    }

    public void setPluginId(int pluginId) {
        this.pluginId = pluginId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getRisk() {
        return risk;
    }

    public void setRisk(int risk) {
        this.risk = risk;
    }

    public int getConfidence() {
        return confidence;
    }

    public void setConfidence(int confidence) {
        this.confidence = confidence;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getParam() {
        return param;
    }

    public void setParam(String param) {
        this.param = param;
    }

    public String getAttack() {
        return attack;
    }

    public void setAttack(String attack) {
        this.attack = attack;
    }

    public String getOtherInfo() {
        return otherInfo;
    }

    public void setOtherInfo(String otherInfo) {
        this.otherInfo = otherInfo;
    }

    public String getSolution() {
        return solution;
    }

    public void setSolution(String solution) {
        this.solution = solution;
    }

    public String getReference() {
        return reference;
    }

    public void setReference(String reference) {
        this.reference = reference;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getInputVector() {
        return inputVector;
    }

    public void setInputVector(String inputVector) {
        this.inputVector = inputVector;
    }

    public int getCweId() {
        return cweId;
    }

    public void setCweId(int cweId) {
        this.cweId = cweId;
    }

    public int getWascId() {
        return wascId;
    }

    public void setWascId(int wascId) {
        this.wascId = wascId;
    }

    public int getSourceId() {
        return sourceId;
    }

    public void setSourceId(int sourceId) {
        this.sourceId = sourceId;
    }

    public String getAlertRef() {
        return alertRef;
    }

    public void setAlertRef(String alertRef) {
        this.alertRef = alertRef;
    }
}
