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
package org.zaproxy.addon.graphql.techdetection;

import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.graphql.GraphQlFingerprinter;
import org.zaproxy.zap.extension.wappalyzer.Application;
import org.zaproxy.zap.extension.wappalyzer.ApplicationMatch;
import org.zaproxy.zap.extension.wappalyzer.ExtensionWappalyzer;
import org.zaproxy.zap.view.ScanPanel;

public class ExtensionTechDetection extends ExtensionAdaptor {

    public static final String NAME = "ExtensionTechDetectionGraphQl";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionWappalyzer.class);

    private static ExtensionWappalyzer extTech;

    public ExtensionTechDetection() {
        super(NAME);
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("graphql.techdetection.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("graphql.techdetection.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        GraphQlFingerprinter.setAppConsumer(this::addApp);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        GraphQlFingerprinter.setAppConsumer(GraphQlFingerprinter.DEFAULT_APP_CONSUMER);
    }

    private static String normalizeSite(URI uri) {
        String lead = uri.getScheme() + "://";
        try {
            return lead + uri.getAuthority();
        } catch (URIException e) {
            // Shouldn't happen, but sure fallback
            return ScanPanel.cleanSiteName(uri.toString(), true);
        }
    }

    private static ApplicationMatch getAppForEngine(String engineId) {
        final String enginePrefix = "graphql.engine." + engineId + ".";

        Application engine = new Application();
        engine.setName(Constant.messages.getString(enginePrefix + "name"));
        engine.setCategories(List.of("GraphQL Engine"));
        engine.setWebsite(Constant.messages.getString(enginePrefix + "docsUrl"));
        engine.setImplies(List.of(Constant.messages.getString(enginePrefix + "technologies")));

        return new ApplicationMatch(engine);
    }

    public void addApp(URI uri, String engineId) {
        getExtTech().addApplicationsToSite(normalizeSite(uri), getAppForEngine(engineId));
    }

    private static ExtensionWappalyzer getExtTech() {
        if (extTech == null) {
            extTech =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionWappalyzer.class);
        }
        return extTech;
    }
}
