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
package org.zaproxy.addon.dev;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.zaproxy.addon.network.server.HttpMessageHandler;

/**
 * A node in the hierarchy of the test server, either a {@link TestDirectory directory} or a {@link
 * TestPage page} in one.
 *
 * <p>A node that builds up state while it is used, for example the tokens it has issued, should
 * register it, with {@link #state(Collection)}, {@link #state(Map)} or {@link #onReset(Runnable)},
 * so that it is cleared by {@link #reset()}, which is called when ZAP's session changes. Settings
 * are not state, so should not be registered.
 */
public abstract class TestNode implements HttpMessageHandler {

    private final String name;
    private final TestProxyServer server;
    private TestDirectory parent;

    private final List<Collection<?>> stateCollections = new ArrayList<>();
    private final List<Map<?, ?>> stateMaps = new ArrayList<>();
    private final List<Runnable> stateResets = new ArrayList<>();

    protected TestNode(TestProxyServer server, String name) {
        this.server = server;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public TestProxyServer getServer() {
        return server;
    }

    public TestDirectory getParent() {
        return parent;
    }

    public void setParent(TestDirectory parent) {
        this.parent = parent;
    }

    /**
     * Registers a collection which holds state, so that it is cleared by {@link #reset()}.
     *
     * <p>For example: {@code private final Set<String> tokens = state(new HashSet<>());}
     *
     * @param collection the collection.
     * @param <C> the type of the collection.
     * @return the given collection.
     */
    protected final <C extends Collection<?>> C state(C collection) {
        stateCollections.add(collection);
        return collection;
    }

    /**
     * Registers a map which holds state, so that it is cleared by {@link #reset()}.
     *
     * <p>For example: {@code private final Map<String, String> sessions = state(new HashMap<>());}
     *
     * @param map the map.
     * @param <M> the type of the map.
     * @return the given map.
     */
    protected final <M extends Map<?, ?>> M state(M map) {
        stateMaps.add(map);
        return map;
    }

    /**
     * Registers what to do to reset state which is not a collection or a map, called by {@link
     * #reset()}.
     *
     * @param reset what to do to reset the state.
     */
    protected final void onReset(Runnable reset) {
        stateResets.add(reset);
    }

    /**
     * Resets any state that was registered, built up while the node was used, so it is as it was
     * when the node was created. It is called when ZAP's session changes.
     *
     * <p>Subclasses which contain other nodes should override this, calling the super
     * implementation, to reset them too.
     */
    public void reset() {
        stateCollections.forEach(Collection::clear);
        stateMaps.forEach(Map::clear);
        stateResets.forEach(Runnable::run);
    }

    /** Tells if any state was registered, for testing. */
    boolean hasRegisteredState() {
        return !stateCollections.isEmpty() || !stateMaps.isEmpty() || !stateResets.isEmpty();
    }
}
