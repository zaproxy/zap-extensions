/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.Enableable;

public class AlertFilter extends Enableable {

    /**
     * The Constant FIELD_SEPARATOR used for separating AlertFilter's field during serialization.
     */
    private static final String FIELD_SEPARATOR = ";";

    // Use -1 for global alert filters
    private int contextId;
    private String ruleId;
    // Use -1 as false positive
    private int newRisk;
    private String parameter;
    private boolean isParameterRegex;
    private String url;
    private boolean isUrlRegex;
    private String attack;
    private boolean isAttackRegex;
    private String evidence;
    private boolean isEvidenceRegex;
    private Set<String> methods;

    private static final Logger LOGGER = LogManager.getLogger(AlertFilter.class);

    public AlertFilter() {
        methods = Set.of();
    }

    public AlertFilter(
            int contextId,
            String ruleId,
            int newRisk,
            String url,
            boolean isUrlRegex,
            String parameter,
            boolean enabled) {
        this(
                contextId,
                ruleId,
                newRisk,
                url,
                isUrlRegex,
                parameter,
                false,
                null,
                false,
                null,
                false,
                enabled);
    }

    public AlertFilter(
            int contextId,
            String ruleId,
            int newRisk,
            String url,
            boolean isUrlRegex,
            String parameter,
            boolean isParameterRegex,
            String attack,
            boolean isAttackRegex,
            String evidence,
            boolean isEvidenceRegex,
            boolean enabled) {
        this(
                contextId,
                ruleId,
                newRisk,
                url,
                isUrlRegex,
                parameter,
                isParameterRegex,
                attack,
                isAttackRegex,
                evidence,
                isEvidenceRegex,
                Set.of(),
                enabled);
    }

    public AlertFilter(
            int contextId,
            String ruleId,
            int newRisk,
            String url,
            boolean isUrlRegex,
            String parameter,
            boolean isParameterRegex,
            String attack,
            boolean isAttackRegex,
            String evidence,
            boolean isEvidenceRegex,
            Set<String> methods,
            boolean enabled) {
        super();
        this.contextId = contextId;
        this.ruleId = ruleId;
        this.newRisk = newRisk;
        this.parameter = parameter;
        this.isParameterRegex = isParameterRegex;
        this.url = url;
        this.isUrlRegex = isUrlRegex;
        this.attack = attack;
        this.isAttackRegex = isAttackRegex;
        this.evidence = evidence;
        this.isEvidenceRegex = isEvidenceRegex;
        setMethods(methods);
        this.setEnabled(enabled);
    }

    public AlertFilter(int contextId, Alert alert) {
        super();
        this.contextId = contextId;
        this.ruleId = alert.getAlertRef();
        this.parameter = alert.getParam();
        this.url = alert.getUri();
        this.attack = alert.getAttack();
        this.evidence = alert.getEvidence();
        this.methods = Set.of(alert.getMethod());
        this.setEnabled(true);
    }

    public int getContextId() {
        return contextId;
    }

    public void setContextId(int contextId) {
        this.contextId = contextId;
    }

    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId;
    }

    public static String getNameForRisk(int risk) {
        switch (risk) {
            case -1:
                return Constant.messages.getString("alertFilters.panel.newalert.fp");
            case Alert.RISK_INFO:
                return Constant.messages.getString("alertFilters.panel.newalert.info");
            case Alert.RISK_LOW:
                return Constant.messages.getString("alertFilters.panel.newalert.low");
            case Alert.RISK_MEDIUM:
                return Constant.messages.getString("alertFilters.panel.newalert.medium");
            case Alert.RISK_HIGH:
                return Constant.messages.getString("alertFilters.panel.newalert.high");
            default:
                return "";
        }
    }

    public String getNewRiskName() {
        return getNameForRisk(this.newRisk);
    }

    public int getNewRisk() {
        return newRisk;
    }

    public void setNewRisk(int newRisk) {
        this.newRisk = newRisk;
    }

    public String getParameter() {
        return parameter;
    }

    public void setParameter(String parameter) {
        this.parameter = parameter;
    }

    public boolean isParameterRegex() {
        return isParameterRegex;
    }

    public void setParameterRegex(boolean isParameterRegex) {
        this.isParameterRegex = isParameterRegex;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean isUrlRegex() {
        return isUrlRegex;
    }

    public void setUrlRegex(boolean isUrlRegex) {
        this.isUrlRegex = isUrlRegex;
    }

    public String getAttack() {
        return attack;
    }

    public void setAttack(String attack) {
        this.attack = attack;
    }

    public boolean isAttackRegex() {
        return isAttackRegex;
    }

    public void setAttackRegex(boolean isAttackRegex) {
        this.isAttackRegex = isAttackRegex;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public boolean isEvidenceRegex() {
        return isEvidenceRegex;
    }

    public void setEvidenceRegex(boolean isEvidenceRegex) {
        this.isEvidenceRegex = isEvidenceRegex;
    }

    public Set<String> getMethods() {
        return methods;
    }

    public void setMethods(Set<String> methods) {
        if (methods == null || methods.isEmpty()) {
            this.methods = Set.of();
            return;
        }

        this.methods =
                methods.stream()
                        .filter(Objects::nonNull)
                        .map(String::trim)
                        .filter(e -> !e.isEmpty())
                        .map(e -> e.toUpperCase(Locale.ROOT))
                        .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Encodes the AlertFilter in a String. Fields that contain strings are Base64 encoded.
     *
     * @param alertFilter the AlertFilter
     * @return the encoded string
     */
    public static String encode(AlertFilter alertFilter) {
        StringBuilder out = new StringBuilder();
        out.append(alertFilter.isEnabled()).append(FIELD_SEPARATOR);
        out.append(alertFilter.getRuleId()).append(FIELD_SEPARATOR);
        out.append(alertFilter.getNewRisk()).append(FIELD_SEPARATOR);
        if (alertFilter.url != null) {
            out.append(Base64.encodeBase64String(alertFilter.url.getBytes()));
        }
        out.append(FIELD_SEPARATOR);
        out.append(alertFilter.isUrlRegex()).append(FIELD_SEPARATOR);
        if (alertFilter.parameter != null) {
            out.append(Base64.encodeBase64String(alertFilter.parameter.getBytes()));
        }
        out.append(FIELD_SEPARATOR);
        out.append(alertFilter.isParameterRegex()).append(FIELD_SEPARATOR);
        if (alertFilter.attack != null) {
            out.append(Base64.encodeBase64String(alertFilter.attack.getBytes()));
        }
        out.append(FIELD_SEPARATOR);
        out.append(alertFilter.isAttackRegex()).append(FIELD_SEPARATOR);
        if (alertFilter.evidence != null) {
            out.append(Base64.encodeBase64String(alertFilter.evidence.getBytes()));
        }
        out.append(FIELD_SEPARATOR);
        out.append(alertFilter.isEvidenceRegex()).append(FIELD_SEPARATOR);
        if (!alertFilter.methods.isEmpty()) {
            String methods =
                    alertFilter.methods.stream()
                            .map(m -> m.getBytes(StandardCharsets.UTF_8))
                            .map(Base64::encodeBase64String)
                            .collect(Collectors.joining(FIELD_SEPARATOR));
            out.append(Base64.encodeBase64String(methods.getBytes(StandardCharsets.UTF_8)));
        }
        out.append(FIELD_SEPARATOR);
        // LOGGER.debug("Encoded AlertFilter: {}", out.toString());
        return out.toString();
    }

    /**
     * Decodes an alert filter from an encoded string. The string provided as input should have been
     * obtained through calls to {@link #encode(AlertFilter)}.
     *
     * @param encodedString the encoded string
     * @return the decoded alert filter
     */
    protected static AlertFilter decode(int contextId, String encodedString) {
        String[] pieces = encodedString.split(FIELD_SEPARATOR, -1);
        AlertFilter alertFilter = null;
        try {
            alertFilter = new AlertFilter();
            alertFilter.setContextId(contextId);
            alertFilter.setEnabled(Boolean.parseBoolean(pieces[0]));
            alertFilter.setRuleId(pieces[1]);
            alertFilter.setNewRisk(Integer.parseInt(pieces[2]));
            alertFilter.setUrl(new String(Base64.decodeBase64(pieces[3])));
            alertFilter.setUrlRegex(Boolean.parseBoolean(pieces[4]));
            alertFilter.setParameter(new String(Base64.decodeBase64(pieces[5])));
            if (pieces.length > 6) {
                // Older versions will not have included these fields
                alertFilter.setParameterRegex(Boolean.parseBoolean(pieces[6]));
                alertFilter.setAttack(new String(Base64.decodeBase64(pieces[7])));
                alertFilter.setAttackRegex(Boolean.parseBoolean(pieces[8]));
                alertFilter.setEvidence(new String(Base64.decodeBase64(pieces[9])));
                alertFilter.setEvidenceRegex(Boolean.parseBoolean(pieces[10]));
            }
            if (pieces.length > 11) {
                alertFilter.setMethods(
                        Set.of(
                                        new String(
                                                        Base64.decodeBase64(pieces[11]),
                                                        StandardCharsets.UTF_8)
                                                .split(FIELD_SEPARATOR))
                                .stream()
                                .map(Base64::decodeBase64)
                                .map(m -> new String(m, StandardCharsets.UTF_8))
                                .collect(Collectors.toSet()));
            }
        } catch (Exception ex) {
            LOGGER.error(
                    "An error occurred while decoding alertFilter from: {}", encodedString, ex);
            return null;
        }
        // LOGGER.debug("Decoded alertFilter: {}", alertFilter);
        return alertFilter;
    }

    public boolean appliesToAlert(Alert alert) {
        return this.appliesToAlert(alert, false);
    }

    public boolean appliesToAlert(Alert alert, boolean ignoreContext) {
        if (!isEnabled()) {
            LOGGER.debug("Filter disabled");
            return false;
        }
        if (!getRuleId().equals(String.valueOf(alert.getPluginId()))
                && !getRuleId().equals(alert.getAlertRef())) {
            LOGGER.debug(
                    "Filter didn't match scan rule ID and alert ref: {} != {} && {} != {}",
                    getRuleId(),
                    alert.getPluginId(),
                    getRuleId(),
                    alert.getAlertRef());
            return false;
        }
        if (!ignoreContext && this.contextId != -1) {
            Context context = Model.getSingleton().getSession().getContext(this.contextId);
            if (!context.isIncluded(alert.getUri()) || context.isExcluded(alert.getUri())) {
                return false;
            }
        }
        if (!matchesStringOrRegex("URL", getUrl(), isUrlRegex(), alert.getUri())) {
            return false;
        }
        if (!matchesStringOrRegex(
                "Parameter", getParameter(), isParameterRegex(), alert.getParam())) {
            return false;
        }
        if (!matchesStringOrRegex("Attack", getAttack(), isAttackRegex(), alert.getAttack())) {
            return false;
        }
        if (!matchesStringOrRegex(
                "Evidence", getEvidence(), isEvidenceRegex(), alert.getEvidence())) {
            return false;
        }
        if (!methods.isEmpty() && !methods.contains(alert.getMethod().toUpperCase(Locale.ROOT))) {
            return false;
        }
        return true;
    }

    private static boolean matchesStringOrRegex(
            String paramName, String paramValue, boolean isRegex, String targetValue) {
        if (paramValue != null && paramValue.length() > 0) {
            if (isRegex) {
                if (!targetValue.matches(paramValue)) {
                    LOGGER.debug(
                            "Filter didn't match {} regex: {} : {}",
                            paramName,
                            paramValue,
                            targetValue);
                    return false;
                }
            } else if (!paramValue.equals(targetValue)) {
                LOGGER.debug(
                        "Filter didn't match {} : {} : {}", paramName, paramValue, targetValue);
                return false;
            }
        }
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((attack == null) ? 0 : attack.hashCode());
        result = prime * result + contextId;
        result = prime * result + ((evidence == null) ? 0 : evidence.hashCode());
        result = prime * result + (isAttackRegex ? 1231 : 1237);
        result = prime * result + (isEvidenceRegex ? 1231 : 1237);
        result = prime * result + (isParameterRegex ? 1231 : 1237);
        result = prime * result + (isUrlRegex ? 1231 : 1237);
        result = prime * result + newRisk;
        result = prime * result + ((parameter == null) ? 0 : parameter.hashCode());
        result = prime * result + (ruleId == null ? 0 : ruleId.hashCode());
        result = prime * result + ((url == null) ? 0 : url.hashCode());
        result = prime * result + methods.hashCode();
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!super.equals(obj)) return false;
        if (getClass() != obj.getClass()) return false;
        AlertFilter other = (AlertFilter) obj;
        if (attack == null) {
            if (other.attack != null) return false;
        } else if (!attack.equals(other.attack)) return false;
        if (contextId != other.contextId) return false;
        if (evidence == null) {
            if (other.evidence != null) return false;
        } else if (!evidence.equals(other.evidence)) return false;
        if (isAttackRegex != other.isAttackRegex) return false;
        if (isEvidenceRegex != other.isEvidenceRegex) return false;
        if (isParameterRegex != other.isParameterRegex) return false;
        if (isUrlRegex != other.isUrlRegex) return false;
        if (newRisk != other.newRisk) return false;
        if (parameter == null) {
            if (other.parameter != null) return false;
        } else if (!parameter.equals(other.parameter)) return false;
        if (!Objects.equals(ruleId, other.ruleId)) {
            return false;
        }
        if (url == null) {
            if (other.url != null) return false;
        } else if (!url.equals(other.url)) return false;
        if (!methods.equals(other.methods)) {
            return false;
        }
        return true;
    }
}
