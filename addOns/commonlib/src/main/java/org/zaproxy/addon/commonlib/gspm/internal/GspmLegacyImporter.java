/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.gspm.internal;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRuleRef;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;
import org.zaproxy.zap.utils.XmlUtils;

/**
 * Converts a legacy {@code .policy} XML file to a {@link GspmPolicy}.
 *
 * <p>The {@code locked} flag is treated as active-scan-only: when {@code true}, only the {@code
 * all.ascan} category rule set is set to {@link AlertThreshold#OFF} rather than the global
 * catch-all, leaving passive scan rules unaffected.
 *
 * @since 1.39.0
 */
public class GspmLegacyImporter {

    private GspmLegacyImporter() {}

    /**
     * Parses a legacy {@code .policy} XML file and returns an equivalent {@link GspmPolicy}.
     *
     * @param file the {@code .policy} file to parse
     * @param ruleNames optional map of rule id → name used to populate rule ref names (may be
     *     empty; missing entries are stored as {@code null})
     * @return the migrated policy, or {@code null} if the file could not be read
     * @throws Exception if XML parsing fails
     */
    public static GspmPolicy importPolicy(File file, Map<Integer, String> ruleNames)
            throws Exception {
        DocumentBuilder db = XmlUtils.newXxeDisabledDocumentBuilderFactory().newDocumentBuilder();
        Document doc = db.parse(file);
        doc.getDocumentElement().normalize();

        Node root = doc.getDocumentElement();

        String policyName = getChildText(root, "policy");
        if (policyName == null || policyName.isBlank()) {
            String fileName = file.getName();
            policyName = fileName.substring(0, fileName.length() - ".policy".length());
        }

        AlertThreshold defaultThreshold = AlertThreshold.MEDIUM;
        AttackStrength defaultStrength = AttackStrength.MEDIUM;
        Node scannerNode = getFirstChildNode(root, "scanner");
        if (scannerNode != null) {
            AlertThreshold t = parseThreshold(getChildText(scannerNode, "level"));
            if (t != null) {
                defaultThreshold = t;
            }
            AttackStrength s = parseStrength(getChildText(scannerNode, "strength"));
            if (s != null) {
                defaultStrength = s;
            }
        }

        // locked=true means only explicitly listed active scan rules are active; scope OFF to
        // all.ascan so passive rules are unaffected.
        boolean locked = "true".equalsIgnoreCase(getChildText(root, "locked"));
        AlertThreshold catchAllThreshold = locked ? AlertThreshold.OFF : defaultThreshold;

        GspmPolicy policy = new GspmPolicy(policyName);
        // Reuse the source file's base name so names with path separators (e.g. "/") still map to a
        // single file in the policies directory.
        String sourceName = file.getName();
        if (sourceName.endsWith(".policy")) {
            policy.setFileName(sourceName.substring(0, sourceName.length() - ".policy".length()));
        }
        GspmRuleSet ascanDefault = policy.findOrCreateCategoryRuleSet("all.ascan");
        ascanDefault.setThresholdEnum(catchAllThreshold);
        ascanDefault.setStrengthEnum(defaultStrength);

        // Per-rule overrides: group rules that share the same threshold+strength into one rule set.
        Map<String, GspmRuleSet> groups = new LinkedHashMap<>();
        Node pluginsNode = getFirstChildNode(root, "plugins");
        if (pluginsNode != null) {
            NodeList children = pluginsNode.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                Node child = children.item(i);
                if (child.getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                }
                String elemName = child.getNodeName();
                if (elemName.length() < 2 || elemName.charAt(0) != 'p') {
                    continue;
                }
                int ruleId;
                try {
                    ruleId = Integer.parseInt(elemName.substring(1));
                } catch (NumberFormatException e) {
                    continue;
                }

                boolean enabled = !"false".equalsIgnoreCase(getChildText(child, "enabled"));
                AlertThreshold ruleThreshold;
                if (!enabled) {
                    ruleThreshold = AlertThreshold.OFF;
                } else {
                    AlertThreshold t = parseThreshold(getChildText(child, "level"));
                    ruleThreshold = t != null ? t : defaultThreshold;
                }
                AttackStrength s = parseStrength(getChildText(child, "strength"));
                AttackStrength ruleStrength = s != null ? s : defaultStrength;

                boolean thresholdDiffers = !ruleThreshold.equals(catchAllThreshold);
                boolean strengthDiffers = !ruleStrength.equals(defaultStrength);
                if (!thresholdDiffers && !strengthDiffers) {
                    continue;
                }

                String groupKey =
                        (thresholdDiffers ? ruleThreshold.name() : "")
                                + "|"
                                + (strengthDiffers ? ruleStrength.name() : "");
                GspmRuleSet group = groups.get(groupKey);
                if (group == null) {
                    group = new GspmRuleSet();
                    if (thresholdDiffers) {
                        group.setThresholdEnum(ruleThreshold);
                    }
                    if (strengthDiffers) {
                        group.setStrengthEnum(ruleStrength);
                    }
                    groups.put(groupKey, group);
                }
                group.addRule(new GspmRuleRef(ruleId, ruleNames.get(ruleId)));
            }
        }
        policy.getRuleSets().addAll(groups.values());

        return policy;
    }

    private static AlertThreshold parseThreshold(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            AlertThreshold t = AlertThreshold.valueOf(value.toUpperCase(Locale.ROOT));
            return t == AlertThreshold.DEFAULT ? null : t;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static AttackStrength parseStrength(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            AttackStrength s = AttackStrength.valueOf(value.toUpperCase(Locale.ROOT));
            return s == AttackStrength.DEFAULT ? null : s;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static Node getFirstChildNode(Node parent, String name) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (name.equals(child.getNodeName())) {
                return child;
            }
        }
        return null;
    }

    private static String getChildText(Node parent, String childName) {
        Node child = getFirstChildNode(parent, childName);
        return child != null ? child.getTextContent().trim() : null;
    }
}
