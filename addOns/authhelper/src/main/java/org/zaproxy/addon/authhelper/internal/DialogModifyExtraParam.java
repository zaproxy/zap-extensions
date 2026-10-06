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
package org.zaproxy.addon.authhelper.internal;

import java.awt.Dialog;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
class DialogModifyExtraParam extends DialogAddExtraParam {

    private static final long serialVersionUID = 1L;

    private ExtraParam original;

    protected DialogModifyExtraParam(Dialog owner) {
        super(
                owner,
                Constant.messages.getString(
                        "authhelper.auth.method.oauth2.extraparams.ui.modify.title"));
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString(
                "authhelper.auth.method.oauth2.extraparams.ui.modify.button");
    }

    public void setParam(ExtraParam param) {
        this.original = param;
        this.param = param;
    }

    @Override
    protected boolean validateFields() {
        return validate(original);
    }

    @Override
    protected void init() {
        getNameTextField().setText(original.getName());
        getNameTextField().discardAllEdits();
        getValueTextField().setText(original.getValue());
        getValueTextField().discardAllEdits();
    }

    @Override
    public void clear() {
        super.clear();
        this.original = null;
    }
}
