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
package org.zaproxy.addon.retire;

import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.addon.retire.model.Repo;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;

public class ExtensionRetire extends ExtensionAdaptor implements RepoHolder, ExampleAlertProvider {

    public static final String NAME = "ExtensionRetire";

    private static final Logger LOGGER = LogManager.getLogger(ExtensionRetire.class);

    private static final String COLLECTION_PATH =
            "/org/zaproxy/addon/retire/resources/jsrepository.json";

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionPassiveScan2.class);

    private Repo repo;
    RetireScanRule passiveScanner; // Package-private for testing

    public ExtensionRetire() {
        super(NAME);
    }

    @Override
    public void init() {
        super.init();

        try {
            this.repo = new Repo(COLLECTION_PATH);
        } catch (IOException e) {
            LOGGER.warn("Failed to load Retire.js collection.", e);
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        passiveScanner = new RetireScanRule(this);
        getPscanExtension().getPassiveScannersManager().add(passiveScanner);
    }

    private static ExtensionPassiveScan2 getPscanExtension() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionPassiveScan2.class);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        if (passiveScanner != null) {
            getPscanExtension().getPassiveScannersManager().remove(passiveScanner);
        }
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("retire.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("retire.name");
    }

    /**
     * Returns the Retire.js repository used by this extension.
     *
     * <p>The returned value may be {@code null} if the repository failed to load during {@link
     * #init()}.
     *
     * @return the loaded {@link Repo}, or {@code null} if loading failed
     */
    @Override
    public Repo getRepo() {
        if (repo == null) {
            LOGGER.warn("Retire.js repository was not loaded, returning null Repo.");
        }
        return repo;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        if (passiveScanner != null) {
            return passiveScanner.getExampleAlerts();
        }
        return List.of();
    }

    public String getHelpLink() {
        if (passiveScanner != null) {
            return passiveScanner.getHelpLink();
        }
        return "";
    }
}
