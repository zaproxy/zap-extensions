/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.saml;

import java.util.Set;

public interface PassiveAttributeChangeListener {

    /**
     * Called on new auto change attribute's value change
     *
     * @param attribute
     */
    void onDesiredAttributeValueChange(Attribute attribute);

    /**
     * Called on new auto change attribute add event
     *
     * @param attribute
     */
    void onAddDesiredAttribute(Attribute attribute);

    /**
     * Called on new auto change attribute's remove event
     *
     * @param attribute
     */
    void onDeleteDesiredAttribute(Attribute attribute);

    /** Get the current auto change attributes */
    Set<Attribute> getDesiredAttributes();
}
