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
package org.zaproxy.addon.paramdigger.gui;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHistoryReferenceContainer;

@SuppressWarnings("serial")
public class ParamDiggerPopUpMenuNote extends PopupMenuItemHistoryReferenceContainer {
    private final ExtensionHistory ext;
    private static final Logger LOGGER = LogManager.getLogger(ParamDiggerPopUpMenuNote.class);

    public ParamDiggerPopUpMenuNote(ExtensionHistory extensionHistory) {
        super(Constant.messages.getString("paramdigger.popup.note"), true);
        this.ext = extensionHistory;
        super.setSize(DisplayUtils.getScaledDimension(200, 20));
    }

    @Override
    public void performAction(HistoryReference href) {
        try {
            ext.showNotesAddDialog(href, href.getHttpMessage().getNote());
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    protected boolean isEnableForInvoker(
            Invoker invoker, HttpMessageContainer httpMessageContainer) {
        return true;
    }
}
