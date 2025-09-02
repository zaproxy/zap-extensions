/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal.ui.diags;

import java.util.function.Predicate;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.authhelper.internal.db.Diagnostic;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticStep;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestScript;

@Data
public class DiagnosticUi {

    private static final Logger LOGGER = LogManager.getLogger(DiagnosticUi.class);

    private String createTimestamp;

    private int id;

    private String authenticationMethod;

    private String context;
    private String user;

    private String url;

    private String afPlan;

    private String script;

    private int steps;

    DiagnosticUi(Diagnostic diagnostic) {
        createTimestamp = diagnostic.getCreateTimestamp().toString();
        id = diagnostic.getId();
        authenticationMethod = diagnostic.getAuthenticationMethod();
        context = diagnostic.getContext();
        user = diagnostic.getUser();
        url = getUrl(diagnostic);
        afPlan = diagnostic.getAfPlan();
        script = diagnostic.getScript();
        steps = diagnostic.getSteps().size();
    }

    private static String getUrl(Diagnostic diagnostic) {
        if (StringUtils.isNotBlank(diagnostic.getScript())) {
            try {
                ExtensionZest ext =
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionZest.class);
                if (ext != null) {
                    String url =
                            ((ZestScript) ext.convertStringToElement(diagnostic.getScript()))
                                    .getStatements().stream()
                                            .filter(ZestClientLaunch.class::isInstance)
                                            .map(ZestClientLaunch.class::cast)
                                            .map(ZestClientLaunch::getUrl)
                                            .findFirst()
                                            .orElse(null);
                    if (StringUtils.isNotBlank(url)) {
                        return url;
                    }
                }
            } catch (Exception e) {
                LOGGER.warn("An error occurred while getting the URL from the script:", e);
            }
        }
        return diagnostic.getSteps().stream()
                .map(DiagnosticStep::getUrl)
                .filter(Predicate.not(String::isEmpty))
                .findFirst()
                .orElse("");
    }
}
