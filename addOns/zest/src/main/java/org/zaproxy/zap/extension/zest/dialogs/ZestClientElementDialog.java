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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zest.core.v1.ZestClientElement;
import org.zaproxy.zest.core.v1.ZestStatement;

public abstract class ZestClientElementDialog extends StandardFieldsDialog implements ZestDialog {

    protected static final String FIELD_WINDOW_HANDLE = "zest.dialog.client.label.windowHandle";
    protected static final String FIELD_ELEMENT_TYPE = "zest.dialog.client.label.elementType";
    protected static final String FIELD_ELEMENT = "zest.dialog.client.label.element";
    protected static final String FIELD_ATTRIBUTE = "zest.dialog.client.label.attribute";

    protected static String ELEMENT_TYPE_PREFIX = "zest.dialog.client.elementType.label.";
    protected static String[] ELEMENT_TYPES = {
        "classname", "cssselector", "id", "linktext", "name", "partiallinktext", "tagname", "xpath"
    };

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;
    private ScriptNode parent = null;
    private ScriptNode child = null;
    private ZestScriptWrapper script = null;
    private ZestStatement request = null;
    private ZestClientElement client = null;
    private boolean add = false;

    public ZestClientElementDialog(ExtensionZest ext, Frame owner, String title, Dimension dim) {
        super(owner, title, dim);
        this.extension = ext;
    }

    public void init(
            ZestScriptWrapper script,
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientElement client,
            boolean add) {
        this.script = script;
        this.add = add;
        this.parent = parent;
        this.child = child;
        this.request = req;
        this.client = client;

        this.removeAllFields();

        // Pull down of all the valid window ids
        List<String> windowIds =
                new ArrayList<String>(script.getZestScript().getClientWindowHandles());
        Collections.sort(windowIds);
        this.addComboField(FIELD_WINDOW_HANDLE, windowIds, client.getWindowHandle());

        String clientType = client.getType();
        if (clientType != null) {
            clientType =
                    Constant.messages.getString(ELEMENT_TYPE_PREFIX + clientType.toLowerCase());
        }
        this.addComboField(FIELD_ELEMENT_TYPE, getElementTypeFields(), clientType);
        this.addTextField(FIELD_ELEMENT, client.getElement());

        setFieldMainPopupMenu(FIELD_ELEMENT);
    }

    private List<String> getElementTypeFields() {
        List<String> list = new ArrayList<String>();
        for (String type : ELEMENT_TYPES) {
            list.add(Constant.messages.getString(ELEMENT_TYPE_PREFIX + type));
        }
        Collections.sort(list);
        return list;
    }

    private String getSelectedElementType() {
        String selectedType = this.getStringValue(FIELD_ELEMENT_TYPE);
        for (String type : ELEMENT_TYPES) {
            if (Constant.messages.getString(ELEMENT_TYPE_PREFIX + type).equals(selectedType)) {
                return type;
            }
        }
        return null;
    }

    protected ExtensionZest getExtension() {
        return extension;
    }

    protected ScriptNode getParentNode() {
        return parent;
    }

    protected ScriptNode getChild() {
        return child;
    }

    protected ZestStatement getRequest() {
        return request;
    }

    protected ZestClientElement getClient() {
        return client;
    }

    protected boolean isAdd() {
        return add;
    }

    @Override
    public void save() {
        client.setWindowHandle(this.getStringValue(FIELD_WINDOW_HANDLE));
        client.setType(getSelectedElementType());
        client.setElement(this.getStringValue(FIELD_ELEMENT));

        this.saveFields();

        if (this.isAdd()) {
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

    public abstract void saveFields();

    @Override
    public String validateFields() {
        if (this.isEmptyField(FIELD_ELEMENT)) {
            return Constant.messages.getString("zest.dialog.client.error.element");
        }

        return null;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return this.script;
    }
}
