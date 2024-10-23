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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.graphql.GraphQlFingerprinter;
import org.zaproxy.addon.graphql.GraphQlFingerprinter.DiscoveredGraphQlEngine;
import org.zaproxy.zap.extension.wappalyzer.Application;
import org.zaproxy.zap.extension.wappalyzer.ApplicationMatch;
import org.zaproxy.zap.extension.wappalyzer.ExtensionWappalyzer;

public class ExtensionTechDetectionGraphQl extends ExtensionAdaptor {

    public static final String NAME = "ExtensionTechDetectionGraphQl";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionWappalyzer.class);

    private static ExtensionWappalyzer extTech;

    public ExtensionTechDetectionGraphQl() {
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
        GraphQlFingerprinter.addEngineHandler(ExtensionTechDetectionGraphQl::addApp);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        GraphQlFingerprinter.resetHandlers();
    }

    private static ApplicationMatch getAppForEngine(DiscoveredGraphQlEngine engine) {
        Application gqlEngine = new Application();
        gqlEngine.setName(engine.getName());
        gqlEngine.setCategories(List.of("GraphQL Engine"));
        gqlEngine.setWebsite(engine.getDocsUrl());
        gqlEngine.setImplies(List.of(engine.getTechnologies()));

        return new ApplicationMatch(gqlEngine);
    }

    private static void addApp(DiscoveredGraphQlEngine engine) {
        getExtTech().addApplicationsToSite(engine.getUri(), getAppForEngine(engine));
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
