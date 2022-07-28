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
package org.zaproxy.zap.extension.sequence;

import java.awt.Component;
import java.text.MessageFormat;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.SequenceScript;

@SuppressWarnings("serial")
public class SequencePopupMenuItem extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private final ExtensionScript extScript;
    public static final Logger logger = LogManager.getLogger(SequencePopupMenuItem.class);
    private ExtensionSequence extension = null;

    public SequencePopupMenuItem(ExtensionSequence extension, ExtensionScript extensionScript) {
        super();
        this.extension = extension;
        this.extScript = extensionScript;
        initialize();
    }

    private void initialize() {
        this.setText(
                extension.getMessages().getString("sequence.popupmenuitem.activeScanSequence"));

        this.addActionListener(
                e -> {
                    try {
                        ScriptWrapper wrapper =
                                (ScriptWrapper)
                                        extScript.getScriptUI().getSelectedNode().getUserObject();
                        SequenceScript scr = extScript.getInterface(wrapper, SequenceScript.class);
                        if (scr != null) {
                            extension.setDirectScanScript(wrapper);
                            scr.scanSequence();
                        } else {
                            String msg =
                                    extension
                                            .getMessages()
                                            .getString(
                                                    "sequence.popupmenuitem.script.error.interface");
                            View.getSingleton()
                                    .showMessageDialog(
                                            MessageFormat.format(msg, wrapper.getName()));
                        }
                    } catch (Exception ex) {
                        logger.warn(
                                "An exception occurred while starting an active scan for a sequence script:",
                                ex);
                    }
                });
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (isScriptTree(invoker)) {
            ScriptNode node = extScript.getScriptUI().getSelectedNode();
            if (node != null) {
                if (node.isTemplate()) {
                    return false;
                }
                ScriptType type = node.getType();
                if (type != null) {
                    if (type.getName().equals(ExtensionSequence.TYPE_SEQUENCE)) {
                        Object obj = node.getUserObject();
                        if (obj != null) {
                            if (obj instanceof ScriptWrapper) {
                                return ((ScriptWrapper) obj).getEngine() != null;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    public boolean isScriptTree(Component component) {
        return this.extScript.getScriptUI() != null
                && component != null
                && this.extScript.getScriptUI().getTreeName().equals(component.getName());
    }
}
