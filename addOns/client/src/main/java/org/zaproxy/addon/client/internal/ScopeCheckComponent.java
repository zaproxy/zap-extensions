/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.client.internal;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import org.jdesktop.swingx.JXRadioGroup;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.client.ClientOptions.ScopeCheck;

public class ScopeCheckComponent {

    private final JXRadioGroup<ScopeCheck> component;

    public ScopeCheckComponent() {
        component = new JXRadioGroup<>(ScopeCheck.values());
        component.setBorder(
                BorderFactory.createTitledBorder(
                        Constant.messages.getString("client.options.label.scope")));

        setScopeCheck(ScopeCheck.getDefault());
    }

    public JComponent getComponent() {
        return component;
    }

    public void setScopeCheck(ScopeCheck value) {
        component.setSelectedValue(value);
    }

    public void setScopeCheck(String value) {
        component.setSelectedValue(ScopeCheck.parse(value));
    }

    public ScopeCheck getScopeCheck() {
        return component.getSelectedValue();
    }
}
