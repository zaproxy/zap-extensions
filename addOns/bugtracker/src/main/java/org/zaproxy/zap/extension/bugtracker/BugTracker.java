/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.bugtracker;

import java.util.Set;
import javax.swing.JPanel;
import org.parosproxy.paros.core.scanner.Alert;

public abstract class BugTracker {

    public abstract String getName();

    public abstract JPanel getConfigPanel();

    public abstract String getId();

    public abstract void setDetails(Set<Alert> alerts);

    public abstract void setDialog(RaiseSemiAutoIssueDialog dialog);

    public abstract void createDialogs();

    public abstract String raise(RaiseSemiAutoIssueDialog dialog);
}
