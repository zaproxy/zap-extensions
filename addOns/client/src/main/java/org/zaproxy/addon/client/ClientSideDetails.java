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
package org.zaproxy.addon.client;

import java.util.HashSet;
import java.util.Set;

public class ClientSideDetails {
    private String name;
    private String url;
    private boolean visited;
    private boolean storage;

    private Set<ClientSideComponent> components = new HashSet<>();

    public ClientSideDetails(String name, String url, boolean visited, boolean storage) {
        this.name = name;
        this.url = url;
        this.visited = visited;
        this.storage = storage;
    }

    public ClientSideDetails(String name, String url) {
        this(name, url, false, false);
    }

    public String getName() {
        return name;
    }

    public String getUrl() {
        return url;
    }

    public boolean isVisited() {
        return visited;
    }

    public Set<ClientSideComponent> getComponents() {
        return components;
    }

    public void setVisited(boolean visited) {
        this.visited = visited;
    }

    public boolean addComponent(ClientSideComponent component) {
        return this.components.add(component);
    }

    public boolean isStorage() {
        return storage;
    }

    public void setStorage(boolean storage) {
        this.storage = storage;
    }
}
