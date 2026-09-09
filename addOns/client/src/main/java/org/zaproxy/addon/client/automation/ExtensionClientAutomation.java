/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.client.automation;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;
import java.util.stream.Collectors;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate;

/**
 * Registers the {@code spiderClient} automation job, and, when the real AJAX Spider add-on is not
 * installed, a {@code spiderAjax} job backed by the Client Spider so that existing plans keep
 * working.
 *
 * <p>If the AJAX Spider add-on is installed later (e.g. via the Marketplace) control of the {@code
 * spiderAjax} job type is handed back to it; if it's later uninstalled control is taken back.
 */
public class ExtensionClientAutomation extends ExtensionAdaptor {

    public static final String NAME = "ExtensionClientAutomation";

    private static final String RESOURCES_DIR = "/org/zaproxy/addon/client/resources/";

    private static final String AJAX_SPIDER_EXTENSION = "ExtensionSpiderAjax";
    private static final String AJAX_SPIDER_ADDON_ID = "spiderAjax";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionClientIntegration.class, ExtensionAutomation.class);

    private ClientSpiderJob job;
    private AjaxSpiderJob ajaxSpiderJob;

    public ExtensionClientAutomation() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
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

        job = new ClientSpiderJob();
        getExtAutomation().registerAutomationJob(job);

        if (!isAjaxSpiderInstalled()) {
            registerAjaxSpiderJob();
        }
    }

    private static ExtensionAutomation getExtAutomation() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
    }

    private static boolean isAjaxSpiderInstalled() {
        return Control.getSingleton().getExtensionLoader().getExtension(AJAX_SPIDER_EXTENSION)
                != null;
    }

    private void registerAjaxSpiderJob() {
        if (ajaxSpiderJob != null) {
            return;
        }
        ajaxSpiderJob = new AjaxSpiderJob();
        getExtAutomation().registerAutomationJob(ajaxSpiderJob);
    }

    private void unregisterAjaxSpiderJob() {
        if (ajaxSpiderJob == null) {
            return;
        }
        getExtAutomation().unregisterAutomationJob(ajaxSpiderJob);
        ajaxSpiderJob = null;
    }

    protected void updateStatus(StatusUpdate statusUpdate) {
        if (!AJAX_SPIDER_ADDON_ID.equals(statusUpdate.getAddOn().getId())) {
            return;
        }
        switch (statusUpdate.getStatus()) {
            case INSTALL:
                // The real AJAX Spider add-on is about to load, give up the spiderAjax job type
                // so it can register its own.
                unregisterAjaxSpiderJob();
                break;
            case UNINSTALLED:
            case SOFT_UNINSTALLED:
                // The real AJAX Spider add-on is gone, take back the spiderAjax job type.
                registerAjaxSpiderJob();
                break;
            default:
                break;
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        getExtAutomation().unregisterAutomationJob(job);
        unregisterAjaxSpiderJob();
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    public static String getResourceAsString(String name) {
        try (InputStream in =
                ExtensionClientIntegration.class.getResourceAsStream(RESOURCES_DIR + name)) {
            return new BufferedReader(new InputStreamReader(in))
                            .lines()
                            .collect(Collectors.joining("\n"))
                    + "\n";
        } catch (Exception e) {
            CommandLine.error(
                    Constant.messages.getString(
                            "client.automation.error.nofile", RESOURCES_DIR + name));
        }
        return "";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("client.automation.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("client.automation.name");
    }
}
