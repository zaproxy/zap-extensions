/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.http.domains;

import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;

public class TrustedDomains {
    private static final Logger LOG = LogManager.getLogger(TrustedDomains.class);

    private String trustedConfig = "";
    private List<Trust> trustedDomainRegexesPatterns = new ArrayList<>();

    public boolean isIncluded(String link) {
        return trustedDomainRegexesPatterns.stream().anyMatch(regex -> regex.isTrusted(link));
    }

    public void update(String trustedConf) {
        if (trustedConf.equals(this.trustedConfig)) {
            return;
        }

        trustedDomainRegexesPatterns.clear();
        this.trustedConfig = trustedConf;
        for (String regex : trustedConf.split(",")) {
            add(regex);
        }
    }

    private void add(String regex) {
        String regexTrim = regex.trim();
        if (!regexTrim.isEmpty()) {
            try {
                add(new RegexTrust(regexTrim));
            } catch (Exception e) {
                LOG.warn(
                        "Invalid regex in rule {} : {}",
                        RuleConfigParam.RULE_DOMAINS_TRUSTED,
                        regex,
                        e);
            }
        }
    }

    public void add(Trust trust) {
        trustedDomainRegexesPatterns.add(trust);
    }
}
