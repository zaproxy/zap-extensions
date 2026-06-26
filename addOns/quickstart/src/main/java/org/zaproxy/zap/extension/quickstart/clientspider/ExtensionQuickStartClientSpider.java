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
package org.zaproxy.zap.extension.quickstart.clientspider;

import java.net.URI;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.spider.ClientSpider;
import org.zaproxy.addon.client.spider.ClientSpiderOptions;
import org.zaproxy.addon.client.spider.ScanOptions;
import org.zaproxy.zap.extension.quickstart.ExtensionQuickStart;
import org.zaproxy.zap.extension.quickstart.ModernSpiderOption;

/**
 * Provides the option to use the Client Spider as the modern spider when running a quick scan. This
 * is a separate extension so that the main extension still loads if the Client add-on is not
 * installed.
 */
public class ExtensionQuickStartClientSpider extends ExtensionAdaptor {

    public static final String NAME = "ExtensionQuickStartClientSpider";

    private static final Logger LOGGER =
            LogManager.getLogger(ExtensionQuickStartClientSpider.class);

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionQuickStart.class, ExtensionClientIntegration.class);

    private ClientSpiderOption clientOption;

    public ExtensionQuickStartClientSpider() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        if (hasView()) {
            this.clientOption = new ClientSpiderOption();
            getExtQuickStart().addModernSpiderOption(clientOption);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (hasView()) {
            getExtQuickStart().removeModernSpiderOption(clientOption);
        }
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("quickstart.clientspider.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("quickstart.clientspider.name");
    }

    private static ExtensionQuickStart getExtQuickStart() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionQuickStart.class);
    }

    private static ExtensionClientIntegration getExtClient() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class);
    }

    private static class ClientSpiderOption implements ModernSpiderOption {

        private int scanId = -1;

        @Override
        public String getName() {
            return Constant.messages.getString("quickstart.modern.option.clientspider");
        }

        @Override
        public String toString() {
            return getName();
        }

        @Override
        public void startScan(URI uri, String browserId) {
            scanId = -1;
            ExtensionClientIntegration extClient = getExtClient();
            ClientSpiderOptions options = extClient.getClientSpiderParam().clone();
            options.setBrowserId(browserId);
            try {
                scanId =
                        extClient.startScan(uri.toString(), options, ScanOptions.builder().build());
            } catch (Exception e) {
                LOGGER.error("Failed to start client spider scan: {}", e.getMessage(), e);
            }
        }

        @Override
        public void stopScan() {
            if (scanId >= 0) {
                new Thread(() -> getExtClient().stopScan(scanId), "ZAP-QuickStart-CSpider-Stop")
                        .start();
            }
        }

        @Override
        public boolean isRunning() {
            if (scanId < 0) {
                return false;
            }
            ClientSpider scan = getExtClient().getScan(scanId);
            return scan != null && !scan.isStopped();
        }
    }
}
