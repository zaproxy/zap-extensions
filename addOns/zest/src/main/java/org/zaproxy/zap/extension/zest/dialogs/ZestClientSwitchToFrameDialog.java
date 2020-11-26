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
package org.zaproxy.zap.extension.zest.dialogs;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zest.core.v1.ZestClientSwitchToFrame;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestClientSwitchToFrameDialog extends StandardFieldsDialog implements ZestDialog {

    private static final String FIELD_WINDOW_HANDLE = "zest.dialog.client.label.windowHandle";
    private static final String FIELD_FRAME_INDEX = "zest.dialog.client.label.frameindex";
    private static final String FIELD_FRAME_NAME = "zest.dialog.client.label.framename";
    private static final String FIELD_PARENT_FRAME = "zest.dialog.client.label.parentframe";

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;
    private ScriptNode parent = null;
    private ScriptNode child = null;
    private ZestScriptWrapper script = null;
    private ZestStatement request = null;
    private ZestClientSwitchToFrame client = null;
    private boolean add = false;

    public ZestClientSwitchToFrameDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(owner, "zest.dialog.clientSwitchToFrame.add.title", dim);
        this.extension = ext;
    }

    public void init(
            ZestScriptWrapper script,
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientSwitchToFrame client,
            boolean add) {
        this.script = script;
        this.add = add;
        this.parent = parent;
        this.child = child;
        this.request = req;
        this.client = client;

        this.removeAllFields();

        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.clientSwitchToFrame.add.title"));
        } else {
            this.setTitle(
                    Constant.messages.getString("zest.dialog.clientSwitchToFrame.edit.title"));
        }

        // Pull down of all the valid window ids
        List<String> windowIds =
                new ArrayList<String>(script.getZestScript().getClientWindowHandles());
        Collections.sort(windowIds);
        this.addComboField(FIELD_WINDOW_HANDLE, windowIds, client.getWindowHandle());

        this.addTextField(FIELD_FRAME_NAME, client.getFrameName());
        this.addNumberField(FIELD_FRAME_INDEX, -1, 1024, client.getFrameIndex());
        this.addCheckBoxField(FIELD_PARENT_FRAME, client.isParent());

        setFieldMainPopupMenu(FIELD_FRAME_NAME);

        // Only allow one choice to be selected
        ((ZapTextField) getField(FIELD_FRAME_NAME))
                .getDocument()
                .addDocumentListener(
                        new DocumentListener() {

                            @Override
                            public void insertUpdate(DocumentEvent e) {
                                checkFieldContent(e);
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e) {
                                checkFieldContent(e);
                            }

                            @Override
                            public void changedUpdate(DocumentEvent e) {
                                checkFieldContent(e);
                            }

                            private void checkFieldContent(DocumentEvent e) {
                                if (e.getDocument().getLength() > 0) {
                                    setFieldValue(FIELD_FRAME_INDEX, -1);
                                }
                            }
                        });
        ((ZapNumberSpinner) getField(FIELD_FRAME_INDEX))
                .addChangeListener(
                        e -> {
                            if (getIntValue(FIELD_FRAME_INDEX) >= 0) {
                                setFieldValue(FIELD_FRAME_NAME, "");
                            }
                        });
        this.addFieldListener(
                FIELD_PARENT_FRAME,
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (getBoolValue(FIELD_PARENT_FRAME)) {
                            setFieldValue(FIELD_FRAME_NAME, "");
                            setFieldValue(FIELD_FRAME_INDEX, -1);
                        }
                    }
                });
    }

    @Override
    public void save() {
        client.setWindowHandle(this.getStringValue(FIELD_WINDOW_HANDLE));
        client.setFrameName(this.getStringValue(FIELD_FRAME_NAME));
        client.setFrameIndex(this.getIntValue(FIELD_FRAME_INDEX));
        client.setParent(this.getBoolValue(FIELD_PARENT_FRAME));

        if (add) {
            if (request == null) {
                extension.addToParent(parent, client);
            } else {
                extension.addAfterRequest(parent, child, request, client);
            }
        } else {
            extension.updated(child);
            extension.display(child, false);
        }
    }

    @Override
    public String validateFields() {
        int setFields = 0;
        if (!isEmptyField(FIELD_FRAME_NAME)) {
            setFields++;
        }
        if (getIntValue(FIELD_FRAME_INDEX) >= 0) {
            setFields++;
        }
        if (getBoolValue(FIELD_PARENT_FRAME)) {
            setFields++;
        }
        if (setFields != 1) {
            return Constant.messages.getString("zest.dialog.client.error.switchToFrame");
        }
        return null;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return this.script;
    }
}
