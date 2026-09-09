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
package org.zaproxy.addon.client.ajax;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate;
import org.zaproxy.zap.extension.api.API;

/**
 * Registers an {@code ajaxSpider} API, backed by the Client Spider, when the real AJAX Spider
 * add-on is not installed. This allows most scripts/clients written for the AJAX Spider API to keep
 * working, using the Client Spider instead. Callers that depend on features specific to the AJAX
 * Spider may still fail.
 *
 * <p>If the AJAX Spider add-on is installed later (e.g. via the Marketplace) control of the {@code
 * ajaxSpider} API prefix is handed back to it; if it's later uninstalled control is taken back.
 */
public class ExtensionClientAjax extends ExtensionAdaptor {

    public static final String NAME = "ExtensionClientAjax";

    private static final String AJAX_SPIDER_EXTENSION = "ExtensionSpiderAjax";
    private static final String AJAX_SPIDER_ADDON_ID = "spiderAjax";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionClientIntegration.class);

    private AjaxSpiderAPI apiImplementor;

    public ExtensionClientAjax() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addAddOnInstallationStatusListener(
                new AddOnInstallationStatusListener() {
                    @Override
                    public void update(StatusUpdate statusUpdate) {
                        if (!AJAX_SPIDER_ADDON_ID.equals(statusUpdate.getAddOn().getId())) {
                            return;
                        }
                        updateStatus(statusUpdate);
                    }
                });

        if (isAjaxSpiderInstalled()) {
            return;
        }
        registerApiImplementor();
    }

    private static boolean isAjaxSpiderInstalled() {
        return Control.getSingleton().getExtensionLoader().getExtension(AJAX_SPIDER_EXTENSION)
                != null;
    }

    private void registerApiImplementor() {
        if (apiImplementor != null) {
            return;
        }
        apiImplementor = new AjaxSpiderAPI();
        API.getInstance().registerApiImplementor(apiImplementor);
    }

    private void unregisterApiImplementor() {
        if (apiImplementor == null) {
            return;
        }
        apiImplementor.stopSpider();
        API.getInstance().removeApiImplementor(apiImplementor);
        apiImplementor = null;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        unregisterApiImplementor();
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("client.ajax.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("client.ajax.name");
    }

    protected void updateStatus(StatusUpdate statusUpdate) {
        if (!AJAX_SPIDER_ADDON_ID.equals(statusUpdate.getAddOn().getId())) {
            return;
        }
        switch (statusUpdate.getStatus()) {
            case INSTALL:
                // The real AJAX Spider add-on is about to load, give up the API
                // prefix so it can register its own implementor.
                unregisterApiImplementor();
                break;
            case UNINSTALLED:
            case SOFT_UNINSTALLED:
                // The real AJAX Spider add-on is gone, take back the API prefix.
                registerApiImplementor();
                break;
            default:
                break;
        }
    }
}
