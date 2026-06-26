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
package org.zaproxy.addon.client.internal;

/** Listener notified when nodes or components are added to a {@link ClientMap}. */
public interface ClientMapListener {

    /**
     * Called when a new node is added to the map.
     *
     * @param url the URL of the added node.
     * @param depth the depth of the node in the map.
     * @param siblings the sibling count of the node (including itself) after insertion.
     * @param source an identifier for the source that triggered the addition, or {@code 0} if the
     *     source is unknown.
     */
    void nodeAdded(String url, int depth, int siblings, int source);

    /**
     * Called when a component is added to a node in the map.
     *
     * @param component the component that was added.
     * @param depth the depth of the node in the map.
     * @param siblings the sibling count of the node (including itself) after insertion.
     * @param source an identifier for the source that triggered the addition, or {@code 0} if the
     *     source is unknown.
     */
    void componentAdded(ClientSideComponent component, int depth, int siblings, int source);

    /**
     * Called when a page-load event is reported for a URL.
     *
     * @param url the URL of the page that loaded.
     * @param source an identifier for the source that triggered the event, or {@code 0} if the
     *     source is unknown.
     */
    default void pageLoaded(String url, int source) {}
}
