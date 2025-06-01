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
import java.awt.Window;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ZestCookieDialog extends StandardFieldsDialog implements ZestDialog {

    private static final String FIELD_PARAM_DOMAIN = "zest.dialog.cookies.label.domain";
    private static final String FIELD_PARAM_NAME = "zest.dialog.cookies.label.name";
    private static final String FIELD_PARAM_VALUE = "zest.dialog.cookies.label.value";
    private static final String FIELD_PARAM_PATH = "zest.dialog.cookies.label.path";

    private static final long serialVersionUID = 1L;

    private CookiesTableModel model = null;
    private boolean add = true;
    private int index = -1;
    private ZestScriptWrapper script;

    public ZestCookieDialog(CookiesTableModel model, Window owner, Dimension dim) {
        super(owner, "zest.dialog.param.add.title", dim);
        this.model = model;
    }

    public void init(
            ZestScriptWrapper script,
            String domain,
            String name,
            String value,
            String path,
            boolean add,
            int index,
            boolean canBeEmpty) {
        this.script = script;
        this.add = add;
        this.index = index;
        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.cookies.add.title"));
        } else {
            this.setTitle(Constant.messages.getString("zest.dialog.cookies.edit.title"));
        }

        this.removeAllFields();

        this.addTextField(FIELD_PARAM_DOMAIN, domain);
        this.addTextField(FIELD_PARAM_NAME, name);
        this.addTextField(FIELD_PARAM_VALUE, value);
        this.addTextField(FIELD_PARAM_PATH, path);
        this.addPadding();

        setFieldMainPopupMenu(FIELD_PARAM_DOMAIN);
        setFieldMainPopupMenu(FIELD_PARAM_NAME);
        setFieldMainPopupMenu(FIELD_PARAM_VALUE);
        setFieldMainPopupMenu(FIELD_PARAM_PATH);
    }

    @Override
    public void save() {
        if (add) {
            this.model.add(
                    this.getStringValue(FIELD_PARAM_DOMAIN),
                    this.getStringValue(FIELD_PARAM_NAME),
                    this.getStringValue(FIELD_PARAM_VALUE),
                    this.getStringValue(FIELD_PARAM_PATH));
        } else {
            this.model.replace(
                    this.index,
                    this.getStringValue(FIELD_PARAM_DOMAIN),
                    this.getStringValue(FIELD_PARAM_NAME),
                    this.getStringValue(FIELD_PARAM_VALUE),
                    this.getStringValue(FIELD_PARAM_PATH));
        }
    }

    @Override
    public String validateFields() {
        if (getStringValue(FIELD_PARAM_NAME).isEmpty()) {
            return Constant.messages.getString("zest.dialog.cookies.error.cookie.name.empty");
        }
        return null;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return script;
    }
}
