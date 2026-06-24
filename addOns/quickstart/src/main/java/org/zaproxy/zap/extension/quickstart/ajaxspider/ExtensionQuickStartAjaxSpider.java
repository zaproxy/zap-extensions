/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart.ajaxspider;

import java.net.URI;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.quickstart.ExtensionQuickStart;
import org.zaproxy.zap.extension.quickstart.ModernSpiderOption;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderParam;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderTarget;
import org.zaproxy.zap.extension.spiderAjax.ExtensionAjax;

/**
 * Provides the option to use the Ajax Spider as the modern spider when running a quick scan. This
 * is a separate extension so that the main extension still loads if the Ajax Spider is not
 * installed.
 */
public class ExtensionQuickStartAjaxSpider extends ExtensionAdaptor {

    public static final String NAME = "ExtensionQuickStartAjaxSpider";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionQuickStart.class, ExtensionAjax.class);

    private AjaxSpiderOption ajaxOption;

    public ExtensionQuickStartAjaxSpider() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        if (hasView()) {
            this.ajaxOption = new AjaxSpiderOption();
            getExtQuickStart().addModernSpiderOption(ajaxOption);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (hasView()) {
            getExtQuickStart().removeModernSpiderOption(ajaxOption);
        }
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("quickstart.ajaxspider.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("quickstart.ajaxspider.name");
    }

    public ExtensionQuickStart getExtQuickStart() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionQuickStart.class);
    }

    private class AjaxSpiderOption implements ModernSpiderOption {

        @Override
        public String getName() {
            return Constant.messages.getString("quickstart.modern.option.ajaxspider");
        }

        @Override
        public String toString() {
            return getName();
        }

        @Override
        public void startScan(URI uri, String browserId) {
            ExtensionAjax extAjax = getExtAjax();
            AjaxSpiderParam options =
                    Model.getSingleton()
                            .getOptionsParam()
                            .getParamSet(AjaxSpiderParam.class)
                            .clone();
            options.setBrowserId(browserId);
            AjaxSpiderTarget.Builder builder =
                    AjaxSpiderTarget.newBuilder(Model.getSingleton().getSession());
            builder.setStartUri(uri);
            builder.setInScopeOnly(false);
            builder.setSubtreeOnly(false);
            builder.setOptions(options);
            extAjax.startScan(builder.build());
        }

        @Override
        public void stopScan() {
            getExtAjax().stopScan();
        }

        @Override
        public boolean isRunning() {
            return getExtAjax().isSpiderRunning();
        }

        private ExtensionAjax getExtAjax() {
            return Control.getSingleton().getExtensionLoader().getExtension(ExtensionAjax.class);
        }
    }
}
