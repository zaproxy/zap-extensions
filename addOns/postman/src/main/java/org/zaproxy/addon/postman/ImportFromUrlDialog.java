/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.postman;

import java.io.IOException;
import javax.swing.JFrame;
import org.parosproxy.paros.Constant;

public class ImportFromUrlDialog extends ImportFromAbstractDialog {

    private static final long serialVersionUID = 1L;
    private static final String MESSAGE_PREFIX = "postman.importfromurldialog.";

    public ImportFromUrlDialog(JFrame parent) {
        super(
                parent,
                Constant.messages.getString(MESSAGE_PREFIX + "title"),
                Constant.messages.getString(MESSAGE_PREFIX + "labelurl"));
    }

    @Override
    protected boolean importDefinition() throws IOException {
        try {
            PostmanParser parser = new PostmanParser();
            parser.importFromUrl(getFromField().getText());

            showMessageDialog(Constant.messages.getString("postman.parse.ok"));
            return true;
        } catch (IllegalArgumentException e) {
            showWarningDialog(e.getMessage());
            return false;
        }
    }
}
