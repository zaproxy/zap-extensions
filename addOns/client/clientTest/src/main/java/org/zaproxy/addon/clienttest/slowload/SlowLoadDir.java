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
package org.zaproxy.addon.clienttest.slowload;

import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * A page which only responds after a delay, so a browser which does not wait for page loads, for
 * example with the {@code none} page load strategy, is still on the initial page, {@code
 * about:home} or {@code about:blank}, when it returns from the navigation.
 */
public class SlowLoadDir extends TestDirectory {

    public SlowLoadDir(TestProxyServer server, String name) {
        super(server, name);
        this.addPage(new SlowLoadPage(server));
    }
}
