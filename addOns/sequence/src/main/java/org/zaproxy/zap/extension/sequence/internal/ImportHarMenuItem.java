/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.sequence.internal;

import org.parosproxy.paros.Constant;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.view.ZapMenuItem;

public class ImportHarMenuItem extends ZapMenuItem {

    private static final long serialVersionUID = 1L;

    private SequenceImportDialog importDialog;

    public ImportHarMenuItem(ScriptType scriptType, ExtensionExim exim, ExtensionZest zest) {
        super("sequence.topmenu.importSequence");

        setToolTipText(Constant.messages.getString("sequence.topmenu.importSequence.tooltip"));

        addActionListener(
                e -> {
                    if (importDialog == null) {
                        importDialog =
                                new SequenceImportDialog(
                                        exim.getView().getMainFrame(), scriptType, exim, zest);
                    }
                    importDialog.setVisible(true);
                });
    }

    public void clear() {
        if (importDialog != null) {
            importDialog.clearFields();
        }
    }

    public void unload() {
        if (importDialog != null) {
            importDialog.dispose();
        }
    }
}
