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
package org.zaproxy.addon.client.internal.graph;

import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.InteractableState;

public sealed interface ClientGraphVertex
        permits ClientGraphVertex.Url, ClientGraphVertex.Component {

    record Url(String url) implements ClientGraphVertex {}

    record Component(ClientSideComponent component, InteractableState state)
            implements ClientGraphVertex {
        public Component(ClientSideComponent component) {
            this(component, null);
        }
    }
}
