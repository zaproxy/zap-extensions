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

import lombok.Data;
import org.zaproxy.addon.authhelper.internal.db.Diagnostic;

@Data
public class DiagnosticUi {

    private String createTimestamp;

    private int id;

    private String authenticationMethod;

    private String context;
    private String user;

    private String script;

    private int steps;

    DiagnosticUi(Diagnostic diagnostic) {
        createTimestamp = diagnostic.getCreateTimestamp().toString();
        id = diagnostic.getId();
        authenticationMethod = diagnostic.getAuthenticationMethod();
        context = diagnostic.getContext();
        user = diagnostic.getUser();
        script = diagnostic.getScript();
        steps = diagnostic.getSteps().size();
    }
}
