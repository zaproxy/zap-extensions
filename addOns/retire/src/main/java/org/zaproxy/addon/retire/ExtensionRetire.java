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
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.addon.retire.model.Repo;
import org.zaproxy.zap.control.AddOn;

public class ExtensionRetire extends ExtensionAdaptor {

    public static final String NAME = "ExtensionRetire";

    private static final Logger LOGGER = LogManager.getLogger(ExtensionRetire.class);

    private static final String COLLECTION_PATH =
            "/org/zaproxy/addon/retire/resources/jsrepository.json";

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionPassiveScan2.class);

    private Repo repo;
    private RetireScanRule rule;

    public ExtensionRetire() {
        super(NAME);
    }

    @Override
    public void init() {
        try {
            this.repo = new Repo(COLLECTION_PATH);
        } catch (IOException e) {
            LOGGER.warn("Failed to load Retire.js collection.", e);
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (repo != null) {
            rule = new RetireScanRule(repo);
            rule.setStatus(AddOn.Status.release);
            getPscanExtension().getPassiveScannersManager().add(rule);
        }
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
        if (rule != null) {
            getPscanExtension().getPassiveScannersManager().remove(rule);
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
     * Returns the Retire.js repository used by this add-on.
     *
     * <p>The returned value may be {@code null} if the repository failed to load during {@link
     * #init()}.
     *
     * @return the loaded {@link Repo}, or {@code null} if loading failed
     */
    Repo getRepo() {
        if (repo == null) {
            LOGGER.warn("Retire.js repository was not loaded, returning null Repo.");
        }
        return repo;
    }

    /** For testing purposes only. */
    RetireScanRule getPassiveScanner() {
        return rule;
    }
}
