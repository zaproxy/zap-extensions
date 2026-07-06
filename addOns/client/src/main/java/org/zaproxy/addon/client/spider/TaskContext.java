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
package org.zaproxy.addon.client.spider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.BooleanSupplier;
import lombok.Getter;
import lombok.Setter;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;
import org.openqa.selenium.WebDriver;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.InteractableState;
import org.zaproxy.addon.client.internal.graph.ClientGraphVertex;
import org.zaproxy.addon.client.spider.ClientSpider.WebDriverProcess;
import org.zaproxy.addon.commonlib.ValueProvider;

@Getter
public class TaskContext {

    private final BooleanSupplier stopped;
    private final ActionWaitStrategy waitStrategy;
    private final WebDriver webDriver;
    private final ValueProvider valueProvider;
    private final ClientMap clientMap;
    private final WebDriverProcess webDriverProcess;

    @Getter @Setter private volatile ClientSideComponent lastActionedComponent;

    private final List<ClientGraphVertex.Component> stateChangedComponents =
            Collections.synchronizedList(new ArrayList<>());

    public TaskContext(
            BooleanSupplier stopped,
            WebDriverProcess webDriverProcess,
            ValueProvider valueProvider,
            ClientMap clientMap) {
        this.stopped = stopped;
        this.webDriverProcess = webDriverProcess;
        this.waitStrategy = webDriverProcess.getWaitStrategy();
        this.webDriver = webDriverProcess.getWebDriver();
        this.valueProvider = valueProvider;
        this.clientMap = clientMap;
    }

    public boolean isStopped() {
        return stopped.getAsBoolean();
    }

    public Graph<ClientGraphVertex, DefaultEdge> getGraph() {
        return clientMap.getGraph();
    }

    public void addNavigationEdge(
            String urlBefore, ClientSideComponent component, String urlAfter) {
        clientMap.addNavigationEdge(urlBefore, component, urlAfter);
    }

    public void addStateChangedComponent(ClientSideComponent component, InteractableState state) {
        if (lastActionedComponent != null) {
            stateChangedComponents.add(new ClientGraphVertex.Component(component, state));
        }
    }

    public List<ClientGraphVertex.Component> getAndClearStateChangedComponents() {
        synchronized (stateChangedComponents) {
            List<ClientGraphVertex.Component> snapshot = new ArrayList<>(stateChangedComponents);
            stateChangedComponents.clear();
            return snapshot;
        }
    }
}
