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
package org.zaproxy.addon.commonlib.scanrules;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.control.AddOn;

public class ScanRuleMetadata {

    private static final ObjectMapper YAML_OBJECT_MAPPER;

    static {
        YAML_OBJECT_MAPPER =
                YAMLMapper.builder()
                        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                        .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS)
                        .build();
        YAML_OBJECT_MAPPER.findAndRegisterModules();
    }

    private int id = -1;
    private String name;
    private String description;
    private String solution;
    private List<String> references;
    private Category category;
    private Risk risk;
    private Confidence confidence;
    private int cweId;
    private int wascId;
    private Map<String, String> alertTags;
    private String otherInfo;
    private AddOn.Status status = AddOn.Status.unknown;
    private String codeLink;
    private String helpLink;

    // Required for Jackson YAML deserialization
    private ScanRuleMetadata() {}

    public ScanRuleMetadata(int id, String name) {
        this.id = id;
        this.name = name;
        validateMetadata(this);
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getSolution() {
        return solution;
    }

    public void setSolution(String solution) {
        this.solution = solution;
    }

    public List<String> getReferences() {
        return references;
    }

    public void setReferences(List<String> references) {
        this.references = references;
    }

    public Category getCategory() {
        return category;
    }

    public void setCategory(Category category) {
        this.category = category;
    }

    public Risk getRisk() {
        return risk;
    }

    public void setRisk(Risk risk) {
        this.risk = risk;
    }

    public Confidence getConfidence() {
        return confidence;
    }

    public void setConfidence(Confidence confidence) {
        this.confidence = confidence;
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

    public Map<String, String> getAlertTags() {
        return alertTags;
    }

    public void setAlertTags(Map<String, String> alertTags) {
        this.alertTags = alertTags;
    }

    public String getOtherInfo() {
        return otherInfo;
    }

    public void setOtherInfo(String otherInfo) {
        this.otherInfo = otherInfo;
    }

    public AddOn.Status getStatus() {
        return status;
    }

    public void setStatus(AddOn.Status status) {
        this.status = status;
    }

    public String getCodeLink() {
        return codeLink;
    }

    public void setCodeLink(String codeLink) {
        this.codeLink = codeLink;
    }

    public String getHelpLink() {
        return helpLink;
    }

    public void setHelpLink(String helpLink) {
        this.helpLink = helpLink;
    }

    public static ScanRuleMetadata fromYaml(String yaml) {
        ScanRuleMetadata metadata;
        try {
            metadata = YAML_OBJECT_MAPPER.readValue(yaml, ScanRuleMetadata.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        validateMetadata(metadata);
        return metadata;
    }

    private static void validateMetadata(ScanRuleMetadata metadata) {
        if (metadata == null || metadata.getId() == -1 || metadata.getName() == null) {
            throw new IllegalArgumentException(
                    Constant.messages.getString("commonlib.scanrules.error.invalidYamlMetadata"));
        }
    }
}
