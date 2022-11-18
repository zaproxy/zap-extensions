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

import static java.util.Objects.requireNonNull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.parosproxy.paros.core.scanner.Alert;

public class SarifRule implements Comparable<SarifRule> {

    private Alert alert;
    private SarifRuleProperties ruleProperties;
    private List<SarifRuleRelationShip> relationShips;

    public SarifRule(Alert alert) {
        requireNonNull(alert, "alert parameter may not be null!");
        this.alert = alert;
        SarifMessage solution =
                SarifMessage.builder().setContentAsHtml(alert.getSolution()).build();

        ruleProperties = new SarifRuleProperties();
        ruleProperties.solution = solution;
        ruleProperties.references =
                SarifHtmlToStringListConverter.DEFAULT.convertToList(alert.getReference());
    }

    public SarifLevel getDefaultLevel() {
        return SarifLevel.fromAlertRisk(alert.getRisk());
    }

    public String getId() {
        return String.valueOf(alert.getPluginId());
    }

    public String getName() {
        return alert.getName();
    }

    public String getFullDescription() {
        return alert.getDescription();
    }

    public String getShortDescription() {
        return alert.getName();
    }

    public SarifRuleProperties getProperties() {
        return ruleProperties;
    }

    @Override
    public int compareTo(SarifRule o) {
        return alert.getPluginId() - o.alert.getPluginId();
    }

    public List<SarifRuleRelationShip> getRelationShips() {
        if (relationShips == null) {
            relationShips = createRelationShips();
        }
        return relationShips;
    }

    private List<SarifRuleRelationShip> createRelationShips() {
        List<SarifRuleRelationShip> list = new ArrayList<>();
        /* CWE relationship */
        if (alert.getCweId() > 0) {

            SarifRuleRelationShip cweRelation = new SarifRuleRelationShip();
            cweRelation.kinds.add("superset");
            cweRelation.target.sarifGuid = SarifGuid.createCweGuid(alert.getCweId());
            cweRelation.target.id = "" + alert.getCweId();
            cweRelation.target.toolComponent = SarifToolData.INSTANCE.getCwe();

            list.add(cweRelation);
        }
        return list;
    }

    public class SarifRuleRelationShip {
        List<String> kinds = new ArrayList<>();
        SarifRuleRelationShipTarget target = new SarifRuleRelationShipTarget();

        public SarifRuleRelationShipTarget getTarget() {
            return target;
        }

        public List<String> getKinds() {
            return kinds;
        }
    }

    public class SarifRuleRelationShipTarget {
        SarifToolComponent toolComponent;
        SarifGuid sarifGuid;
        String id;

        public SarifToolComponent getToolComponent() {
            return toolComponent;
        }

        public String getGuid() {
            return sarifGuid.getGuid();
        }

        public String getId() {
            return id;
        }
    }

    public class SarifRuleProperties {
        private SarifMessage solution;
        private List<String> references;

        public Collection<String> getReferences() {
            return references;
        }

        public SarifMessage getSolution() {
            return solution;
        }

        public String getConfidence() {
            switch (alert.getConfidence()) {
                case Alert.CONFIDENCE_FALSE_POSITIVE:
                    return "false-positive";
                case Alert.CONFIDENCE_MEDIUM:
                    return "medium";
                case Alert.CONFIDENCE_HIGH:
                    return "high";
                case Alert.CONFIDENCE_LOW:
                    return "low";
                case Alert.CONFIDENCE_USER_CONFIRMED:
                    return "confirmed";
                default:
                    return "unknown";
            }
        }
    }
}
