/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.replacer;

import java.util.List;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.utils.Enableable;

class ReplacerParamRule extends Enableable {

    public enum MatchType {
        REQ_HEADER,
        REQ_HEADER_STR,
        REQ_BODY_STR,
        RESP_HEADER,
        RESP_HEADER_STR,
        RESP_BODY_STR
    }

    private String description;
    private String matchString;
    private String replacement;
    private String escapedReplacement;
    private MatchType matchType;
    private boolean matchRegex;
    private List<Integer> initiators;

    public ReplacerParamRule() {
        this("", MatchType.RESP_BODY_STR, "");
    }

    public ReplacerParamRule(String description, MatchType matchType) {
        this(description, matchType, "", false, "", null, false);
    }

    public ReplacerParamRule(String description, MatchType matchType, String matchString) {
        this(description, matchType, matchString, false, "", null, false);
    }

    /**
     * Constructor
     *
     * @param description whatever makes sense to the user
     * @param matchType the type of matching to be performed
     * @param matchString the string to match against
     * @param matchRegex true if the matchString is a regex
     * @param replacement the string to replace with
     * @param initiators a list of initiators as defined in {@link
     *     org.parosproxy.paros.network.HttpSender}
     * @param enabled true if the rule is enabled
     */
    public ReplacerParamRule(
            String description,
            MatchType matchType,
            String matchString,
            boolean matchRegex,
            String replacement,
            List<Integer> initiators,
            boolean enabled) {
        super(enabled);

        this.description = description;
        this.matchType = matchType;
        this.matchString = matchString;
        this.matchRegex = matchRegex;
        this.escapedReplacement = HexString.compile(replacement);
        this.replacement = replacement;
        this.initiators = initiators;
    }

    public ReplacerParamRule(ReplacerParamRule token) {
        this(
                token.description,
                token.matchType,
                token.matchString,
                token.matchRegex,
                token.replacement,
                token.initiators,
                token.isEnabled());
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getMatchString() {
        return matchString;
    }

    public void setMatchString(String matchString) {
        this.matchString = matchString;
    }

    public MatchType getMatchType() {
        return matchType;
    }

    public void setMatchType(MatchType matchType) {
        this.matchType = matchType;
    }

    public boolean isMatchRegex() {
        return matchRegex;
    }

    public void setMatchRegex(boolean matchRegex) {
        this.matchRegex = matchRegex;
    }

    public String getReplacement() {
        return replacement;
    }

    public void setReplacement(String replacement) {
        this.replacement = replacement;
    }

    String getEscapedReplacement() {
        return escapedReplacement;
    }

    public List<Integer> getInitiators() {
        return initiators;
    }

    public void setInitiators(List<Integer> initiators) {
        this.initiators = initiators;
    }

    public boolean appliesToInitiator(int initiator) {
        if (initiator == HttpSender.CHECK_FOR_UPDATES_INITIATOR) {
            return false;
        }
        return appliesToAllInitiators() || initiators.contains(initiator);
    }

    public boolean appliesToAllInitiators() {
        return initiators == null || initiators.isEmpty();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((description == null) ? 0 : description.hashCode());
        result = prime * result + ((initiators == null) ? 0 : initiators.hashCode());
        result = prime * result + (matchRegex ? 1231 : 1237);
        result = prime * result + ((matchString == null) ? 0 : matchString.hashCode());
        result = prime * result + ((matchType == null) ? 0 : matchType.hashCode());
        result = prime * result + ((replacement == null) ? 0 : replacement.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        ReplacerParamRule other = (ReplacerParamRule) obj;
        if (description == null) {
            if (other.description != null) return false;
        } else if (!description.equals(other.description)) return false;
        if (initiators == null) {
            if (other.initiators != null) return false;
        } else if (!initiators.equals(other.initiators)) return false;
        if (matchRegex != other.matchRegex) return false;
        if (matchString == null) {
            if (other.matchString != null) return false;
        } else if (!matchString.equals(other.matchString)) return false;
        if (matchType != other.matchType) return false;
        if (replacement == null) {
            if (other.replacement != null) return false;
        } else if (!replacement.equals(other.replacement)) return false;
        return true;
    }
}
