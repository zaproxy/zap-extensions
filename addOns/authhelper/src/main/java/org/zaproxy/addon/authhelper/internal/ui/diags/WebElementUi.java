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
package org.zaproxy.addon.authhelper.internal.ui.diags;

import lombok.Data;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticWebElement;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticWebElement.SelectorType;

@Data
public class WebElementUi {

    private Integer formIndex;

    private String tagName;
    private String attributeType;
    private String attributeId;
    private String attributeName;
    private String attributeValue;
    private String text;

    private boolean displayed;
    private boolean enabled;

    private String selector;

    public WebElementUi(DiagnosticWebElement webElement) {
        formIndex = webElement.getFormIndex();

        tagName = webElement.getTagName();
        attributeType = webElement.getAttributeType();
        attributeId = webElement.getAttributeId();
        attributeName = webElement.getAttributeName();
        attributeValue = webElement.getAttributeValue();
        text = webElement.getText();

        displayed = webElement.isDisplayed();
        enabled = webElement.isEnabled();

        selector = createSelector(webElement);
    }

    private String createSelector(DiagnosticWebElement webElement) {
        SelectorType selectorType = webElement.getSelectorType();
        if (selectorType != null) {
            return Constant.messages.getString(
                    selectorType == SelectorType.CSS
                            ? "authhelper.authdiags.panel.table.steps.webelement.selector.css"
                            : "authhelper.authdiags.panel.table.steps.webelement.selector.xpath",
                    webElement.getSelectorValue());
        }
        return "";
    }
}
