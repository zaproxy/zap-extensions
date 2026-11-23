/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
import org.zaproxy.zap.view.StandardFieldsDialog;

/** A dialog to add or modify a selector of the shadow path. */
@SuppressWarnings("serial")
public class ZestShadowPathEntryDialog extends StandardFieldsDialog {

    private static final String FIELD_SELECTOR = "zest.dialog.shadowPath.label.selector";

    private static final long serialVersionUID = 1L;

    private final ShadowPathTableModel model;
    private boolean add = true;
    private int index = -1;

    public ZestShadowPathEntryDialog(ShadowPathTableModel model, Window owner, Dimension dim) {
        super(owner, "zest.dialog.shadowPath.add.title", dim);
        this.model = model;
    }

    public void init(String selector, boolean add, int index) {
        this.add = add;
        this.index = index;
        setTitle(
                Constant.messages.getString(
                        add
                                ? "zest.dialog.shadowPath.add.title"
                                : "zest.dialog.shadowPath.edit.title"));

        removeAllFields();

        addTextField(FIELD_SELECTOR, selector);
        addPadding();

        setFieldMainPopupMenu(FIELD_SELECTOR);
    }

    @Override
    public void save() {
        String selector = getStringValue(FIELD_SELECTOR).trim();
        if (add) {
            model.add(selector);
        } else {
            model.replace(index, selector);
        }
    }

    @Override
    public String validateFields() {
        if (getStringValue(FIELD_SELECTOR).trim().isEmpty()) {
            return Constant.messages.getString("zest.dialog.shadowPath.error.selector");
        }
        return null;
    }
}
