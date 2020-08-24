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

import java.awt.Dialog;
import org.parosproxy.paros.Constant;

public class DialogModifyAlertFilter extends DialogAddAlertFilter {

    private static final long serialVersionUID = 7828871270310672334L;
    private static final String DIALOG_TITLE =
            Constant.messages.getString("alertFilters.dialog.modify.title");

    public DialogModifyAlertFilter(ExtensionAlertFilters extension, Dialog owner) {
        super(extension, owner, DIALOG_TITLE);
    }

    @Override
    public void setAlertFilter(AlertFilter alertFilter) {
        super.setAlertFilter(alertFilter);
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("alertFilters.dialog.modify.button.confirm");
    }
}
