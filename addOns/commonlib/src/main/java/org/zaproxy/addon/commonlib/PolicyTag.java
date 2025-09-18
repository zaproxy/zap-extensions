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
package org.zaproxy.addon.commonlib;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Tags to be associated with standardized scan policies which will be distributed as an add-on.
 *
 * @since 1.29.0
 */
public enum PolicyTag {
    DEV_CICD("Dev CICD.policy", "Developer CI/CD", "scanpolicies"),
    DEV_STD("Dev Standard.policy", "Developer Standard", "scanpolicies"),
    DEV_FULL("Dev Full.policy", "Developer Full", "scanpolicies"),
    /**
     * @since 1.36.0
     */
    QA_CICD("QA CICD.policy", "QA CI/CD", "scanpolicies"),
    QA_STD("QA Standard.policy", "QA Standard", "scanpolicies"),
    QA_FULL("QA Full.policy", "QA Full", "scanpolicies"),
    API("API.policy", "API", "scanpolicies"),
    /**
     * For rules believed to be of interest to Penetration Testers. Essentially everything other
     * than Example rules.
     *
     * @since 1.32.0
     */
    PENTEST("Pen Test.policy", "Penetration Tester", "scanpolicies"),

    SEQUENCE("Sequence.policy", "Sequence", "sequence");

    protected static final String PREFIX = "POLICY_";

    private final String tag;
    private final String fileName;
    private final String policyName;
    private final String addonId;

    private PolicyTag(String fileName, String policyName, String addonId) {
        this.tag = PREFIX + this.name();
        this.fileName = fileName;
        this.policyName = policyName;
        this.addonId = addonId;
    }

    public String getTag() {
        return this.tag;
    }

    public String getFileName() {
        return fileName;
    }

    public String getPolicyName() {
        return policyName;
    }

    public String getAddonId() {
        return addonId;
    }

    public static List<String> getAllTags() {
        return Stream.of(PolicyTag.values()).map(PolicyTag::getTag).collect(Collectors.toList());
    }
}
