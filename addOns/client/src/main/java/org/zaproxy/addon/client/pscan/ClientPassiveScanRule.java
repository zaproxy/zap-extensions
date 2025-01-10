/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.client.pscan;

import org.zaproxy.addon.client.internal.ReportedObject;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;

public interface ClientPassiveScanRule extends ExampleAlertProvider {

    String getName();

    int getId();

    default void scanReportedObject(ReportedObject obj, ClientPassiveScanHelper helper) {}

    void setEnabled(boolean enabled);

    boolean isEnabled();

    /** Returns a link to the help on the ZAP website * */
    public String getHelpLink();
}
