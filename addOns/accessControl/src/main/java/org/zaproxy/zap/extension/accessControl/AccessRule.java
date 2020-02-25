/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.accessControl;

import org.parosproxy.paros.Constant;

/**
 * An access rule that can correspond for a node of a website. The rules are configured for a
 * Context and, for each User of that Context, each web page node will be associated to one of the
 * following values:
 *
 * <ul>
 *   <li>{@link #ALLOWED} - the resource can be accessed by the User to which the rule refers
 *   <li>{@link #DENIED} - the resource should not be accessed by the User to which the rule refers
 *   <li>{@link #UNKNOWN} - there is no information regarding whether the resource should or
 *       shouldn't be accessible to the User to which the rule refers
 * </ul>
 *
 * <p>However, during the configuration of rules, the users can set the access rule to one of the
 * following: {@literal ALLOWED}, {@literal DENIED} or {@literal INHERIT}. The latter is used as
 * follows:
 *
 * <ul>
 *   <li>{@link #INHERIT} - The rule for the node is inferred based on the closest ancestor with an
 *       explicitly set rule
 *
 * @author cosminstefanxp
 */
public enum AccessRule {
    /**
     * This rule is associated to resources that can be accessed by the User to which the rule
     * refers.
     */
    ALLOWED(Constant.messages.getString("accessControl.accessRule.allowed")),
    /**
     * This rule is associated to resources that should not be accessed by the User to which the
     * rule refers.
     */
    DENIED(Constant.messages.getString("accessControl.accessRule.denied")),
    /**
     * This rule is associated to resources for which there is no information regarding whether the
     * resource should or shouldn't be accessible to the User to which the rule refers
     */
    UNKNOWN(Constant.messages.getString("accessControl.accessRule.unknown")),
    /**
     * This rule is set, during configuration, to nodes whose rule should be inferred based on the
     * closest ancestor with an explicitly set rule.
     */
    INHERIT(Constant.messages.getString("accessControl.accessRule.inherited"));

    private final String localizedName;

    private AccessRule(String localizedName) {
        this.localizedName = localizedName;
    }

    /** Returns a localized name of the access rule. */
    @Override
    public String toString() {
        return localizedName;
    }
}
