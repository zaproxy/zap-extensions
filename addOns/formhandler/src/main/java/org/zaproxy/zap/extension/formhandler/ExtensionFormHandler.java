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
package org.zaproxy.zap.extension.formhandler;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.zaproxy.zap.extension.params.ExtensionParams;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.model.DefaultValueGenerator;

public class ExtensionFormHandler extends ExtensionAdaptor {

    public static final String NAME = "ExtensionFormHandler";

    protected static final String PREFIX = "formhandler";

    private FormHandlerParam param;

    private OptionsFormHandlerPanel optionsFormHandlerPanel;
    private PopupMenuAddFormhandlerParam popupMenuAddFormhandlerParam;

    public ExtensionFormHandler() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(getParam());
        ExtensionLoader extLoader = Control.getSingleton().getExtensionLoader();
        ExtensionSpider extension = extLoader.getExtension(ExtensionSpider.class);
        if (extension != null) {
            extension.setValueGenerator(new FormHandlerValueGenerator(getParam()));
        }

        if (getView() != null) {
            extensionHook.getHookView().addOptionPanel(getOptionsFormHandlerPanel());
            if (extLoader.isExtensionEnabled(ExtensionParams.NAME)) {
                extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuAddFormhandlerParam());
            }
        }
    }

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed
        // from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        ExtensionSpider extension =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.class);
        if (extension != null) {
            extension.setValueGenerator(new DefaultValueGenerator());
        }
    }

    // Method for creating and obtaining the Options Panel
    private OptionsFormHandlerPanel getOptionsFormHandlerPanel() {
        if (optionsFormHandlerPanel == null) {
            optionsFormHandlerPanel = new OptionsFormHandlerPanel();
        }
        return optionsFormHandlerPanel;
    }

    protected FormHandlerParam getParam() {
        if (param == null) {
            param = new FormHandlerParam();
        }
        return param;
    }

    public List<String> getFormHandlerFieldNames() {
        return this.getParam().getEnabledFieldsNames();
    }

    public void addFormHandlerFieldName(String field, String value) {
        this.getParam().addField(field, value);
    }

    public void removeFormHandlerFieldName(String field) {
        this.getParam().removeField(field);
    }

    private PopupMenuAddFormhandlerParam getPopupMenuAddFormhandlerParam() {
        if (popupMenuAddFormhandlerParam == null) {
            popupMenuAddFormhandlerParam = new PopupMenuAddFormhandlerParam();
        }
        return popupMenuAddFormhandlerParam;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".options.desc");
    }
}
