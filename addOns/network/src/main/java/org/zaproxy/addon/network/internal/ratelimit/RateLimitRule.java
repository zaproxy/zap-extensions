/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ratelimit;

import io.netty.util.NetUtil;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.utils.Enableable;

public class RateLimitRule extends Enableable {
    /** How to group hosts when limiting the request rate. */
    public enum GroupBy {
        RULE,
        HOST;

        public String getLabel() {
            return Constant.messages.getString(
                    "network.ui.ratelimit.groupby." + name().toLowerCase(Locale.ROOT));
        }
    }

    /** Description of the rule, also used as a unique identifier. */
    private String description;

    /** The string to match against the URI host (no protocol, port, path, etc.) */
    private String matchString;

    /** Indicates if matchString is a regular expression (true). */
    private boolean matchRegex;

    private int requestsPerSecond;

    /** How to group hosts when applying rate limiting. */
    private GroupBy groupBy = GroupBy.RULE;

    public static boolean isIpAddress(String value) {
        return value != null
                && !value.isEmpty()
                && (NetUtil.isValidIpV4Address(value) || NetUtil.isValidIpV6Address(value));
    }

    public RateLimitRule() {
        this("", "", false);
    }

    public RateLimitRule(String description, String matchString, boolean enabled) {
        this(description, matchString, false, 1, GroupBy.RULE, enabled);
    }

    /**
     * Constructor
     *
     * @param description whatever makes sense to the user
     * @param matchString the string to match against the host name
     * @param matchRegex true if the matchString is a regex
     * @param requestsPerSecond the maximum requests per second
     * @param groupBy how to group hosts
     * @param enabled true if the rule is enabled
     */
    public RateLimitRule(
            String description,
            String matchString,
            boolean matchRegex,
            int requestsPerSecond,
            GroupBy groupBy,
            boolean enabled) {
        super(enabled);

        this.description = description;
        this.matchString = matchString;
        this.matchRegex = matchRegex;
        this.requestsPerSecond = requestsPerSecond;
        this.groupBy = groupBy;
    }

    public RateLimitRule(RateLimitRule token) {
        this(
                token.description,
                token.matchString,
                token.matchRegex,
                token.requestsPerSecond,
                token.groupBy,
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

    public boolean isMatchRegex() {
        return matchRegex;
    }

    public void setMatchRegex(boolean matchRegex) {
        this.matchRegex = matchRegex;
    }

    public int getRequestsPerSecond() {
        return requestsPerSecond;
    }

    public void setRequestsPerSecond(int requestsPerSecond) {
        this.requestsPerSecond = requestsPerSecond;
    }

    public GroupBy getGroupBy() {
        return groupBy;
    }

    public void setGroupBy(GroupBy groupBy) {
        this.groupBy = groupBy;
    }

    public boolean appliesToInitiator(int initiator) {
        return true;
    }

    public boolean matches(HttpMessage msg) {
        String host;
        try {
            host = msg.getRequestHeader().getURI().getHost();
        } catch (URIException e) {
            return false;
        }
        if (!matchRegex) {
            if (host.equalsIgnoreCase(matchString)) {
                return true;
            }
            // IP address requires exact match
            if (isIpAddress(host) || isIpAddress(matchString)) {
                return false;
            }
            // special handling for not a regex based on DNS conventions
            // if we have one or two element, do a suffix match
            String[] matchSplit = matchString.split("[.]");
            if (matchSplit.length > 2) {
                return false;
            }
            return host.endsWith("." + matchString);
        }
        return Pattern.compile(matchString, Pattern.CASE_INSENSITIVE).matcher(host).matches();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((description == null) ? 0 : description.hashCode());
        result = prime * result + (matchRegex ? 1231 : 1237);
        result = prime * result + ((matchString == null) ? 0 : matchString.hashCode());
        result = prime * result + requestsPerSecond;
        result = prime * result + groupBy.hashCode();
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
        RateLimitRule other = (RateLimitRule) obj;
        return Objects.equals(description, other.description)
                && Objects.equals(matchString, other.matchString)
                && matchRegex == other.matchRegex
                && requestsPerSecond == other.requestsPerSecond
                && groupBy == other.groupBy;
    }

    /**
     * Determines if this rule is equivalent to the argument, i.e. should be considered a duplicate.
     *
     * @param rule the other rule
     * @return true if equivalent/duplicate, including if the this and rule are the same object
     */
    public boolean equivalentTo(RateLimitRule rule) {
        if (this == rule) {
            return true;
        }
        if (Objects.equals(description, rule.getDescription())) {
            return true;
        }
        if (matchRegex == rule.isMatchRegex()) {
            return Objects.equals(matchString, rule.getMatchString());
        }
        return false;
    }
}
