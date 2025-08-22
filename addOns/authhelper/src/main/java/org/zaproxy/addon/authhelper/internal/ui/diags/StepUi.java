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

import java.util.Base64;
import java.util.List;
import lombok.Data;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticMessage;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticStep;

@Data
public class StepUi {

    private static final byte[] EMPTY_ARRAY = {};

    private String createTimestamp;
    private int number;
    private String url;
    private String description;
    private WebElementUi webElement;
    private byte[] screenshotData;

    private List<Integer> messagesIds;
    private List<WebElementUi> webElements;
    private List<BrowserStorageUi> browserStorageItems;

    private String label;

    StepUi(int number, DiagnosticStep step) {
        createTimestamp = step.getCreateTimestamp().toString();
        this.number = number;
        url = step.getUrl();
        description = step.getDescription();
        webElement = step.getWebElement() != null ? new WebElementUi(step.getWebElement()) : null;
        screenshotData =
                step.getScreenshot() != null
                        ? Base64.getDecoder().decode(step.getScreenshot().getData())
                        : EMPTY_ARRAY;
        messagesIds = step.getMessages().stream().map(DiagnosticMessage::getMessageId).toList();
        webElements = step.getWebElements().stream().map(WebElementUi::new).toList();
        browserStorageItems =
                step.getBrowserStorageItems().stream().map(BrowserStorageUi::new).toList();

        label =
                Constant.messages.getString(
                        "authhelper.authdiags.panel.step.label", number, description);
    }

    public boolean hasWebElement() {
        return webElement != null;
    }

    public boolean hasScreenshot() {
        return screenshotData != EMPTY_ARRAY;
    }
}
