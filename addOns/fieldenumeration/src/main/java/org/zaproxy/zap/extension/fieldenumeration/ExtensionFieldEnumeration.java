/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.fieldenumeration;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.api.API;

public class ExtensionFieldEnumeration extends ExtensionAdaptor {

    private PopupMenuField popupMenuField = null;
    private FieldEnumeration fieldEnumeration = null;
    private EnumerationAPI enumAPI = null;
    private boolean field;
    public static final String NAME = "ExtensionFieldEnumeration";
    protected static final String PREFIX = "fieldenumeration";

    public ExtensionFieldEnumeration() {
        super(NAME);
    }

    @Override
    public void init() {
        super.init();
        enumAPI = new EnumerationAPI(this);
        field = false;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuField());
        }
        API.getInstance().registerApiImplementor(enumAPI);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        API.getInstance().removeApiImplementor(enumAPI);
    }

    private PopupMenuField getPopupMenuField() {
        if (popupMenuField == null) {
            popupMenuField = new PopupMenuField(this);
        }
        return popupMenuField;
    }

    private void displayFieldEnumeration(HistoryReference ref) {
        fieldEnumeration.setHistoryRef(ref);
        fieldEnumeration.pack();
        fieldEnumeration.setVisible(true);
    }

    public void showFieldEnumeration(HistoryReference ref) {
        if (fieldEnumeration == null) {
            fieldEnumeration = new FieldEnumeration(getView().getMainFrame(), false);
            displayFieldEnumeration(ref);
        } else if (!fieldEnumeration.isVisible()) {
            displayFieldEnumeration(ref);
        }
    }

    void enumerateField(String url, String form, String charset) {
        // TODO - Used by API
    }

    boolean isField() {
        return field;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString(PREFIX + ".name");
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
