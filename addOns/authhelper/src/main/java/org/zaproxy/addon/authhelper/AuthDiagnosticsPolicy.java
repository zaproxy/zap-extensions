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
package org.zaproxy.addon.authhelper;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.AuthenticationDiagnostics.Retention;
import org.zaproxy.addon.authhelper.internal.db.Diagnostic;
import org.zaproxy.zap.users.User;

/**
 * Failure-only retention of authentication diagnostics, configured per context (by name) by the
 * {@code diagnostics} automation job.
 *
 * <p>While active for a context, diagnostics are not persisted when closed. Instead, the outcome of
 * the authentication attempt decides: successes are dropped, failures are persisted and, for {@link
 * Mode#AUTH_FAILURE_ROLLING}, older failures beyond the configured count are deleted.
 *
 * <p>Plans using the same context name share one configuration, the core notifications only
 * identify the {@link User}.
 */
public class AuthDiagnosticsPolicy implements Retention {

    private static final Logger LOGGER = LogManager.getLogger(AuthDiagnosticsPolicy.class);

    private static final AuthDiagnosticsPolicy INSTANCE = new AuthDiagnosticsPolicy();

    private final ConcurrentMap<String, ContextState> contexts = new ConcurrentHashMap<>();
    private static final Class<?> LISTENER_CLASS = findListenerClass();

    private Object listener;

    AuthDiagnosticsPolicy() {}

    public static AuthDiagnosticsPolicy getInstance() {
        return INSTANCE;
    }

    /** Tells whether the core supports the authentication listener, required by the policy. */
    public static boolean isSupported() {
        return LISTENER_CLASS != null;
    }

    private static Class<?> findListenerClass() {
        try {
            return Class.forName("org.zaproxy.zap.users.AuthenticationListener");
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    /**
     * Activates the policy for the given context, replacing any previous configuration for it.
     *
     * @param context the name of the context.
     * @param mode the retention mode.
     * @param count the number of failures to retain, only used with {@link
     *     Mode#AUTH_FAILURE_ROLLING}.
     * @return {@code true} if the policy is active, {@code false} if the core does not support it,
     *     in which case diagnostics are persisted as usual.
     */
    public synchronized boolean configure(String context, Mode mode, int count) {
        if (!register()) {
            return false;
        }
        contexts.put(
                context,
                mode == Mode.AUTH_ON_FAILURE
                        ? new ContextState(1, false)
                        : new ContextState(Math.max(1, count), true));
        return true;
    }

    /**
     * Deactivates the policy for the given context, and unregisters from the core if no other
     * context is active.
     *
     * @param context the name of the context.
     */
    public synchronized void clear(String context) {
        contexts.remove(context);
        if (contexts.isEmpty()) {
            unregister();
        }
    }

    /** Deactivates the policy for all contexts and unregisters from the core. */
    public synchronized void clearAll() {
        contexts.clear();
        unregister();
    }

    @Override
    public boolean isActive(String context) {
        return context != null && contexts.containsKey(context);
    }

    @Override
    public boolean isDetailed(String context) {
        ContextState state = contexts.get(context);
        return state != null && state.detailed;
    }

    @Override
    public void defer(Diagnostic diagnostic) {
        ContextState state = contexts.get(diagnostic.getContext());
        if (state != null) {
            state.pending.put(diagnostic.getUser(), diagnostic);
        }
    }

    // TODO Replace the reflection with an AuthenticationListener implementation and direct calls
    // to User.add/removeAuthenticationListener, once targeting a core with them (zaproxy#9465).
    boolean register() {
        if (listener != null) {
            return true;
        }
        if (LISTENER_CLASS == null) {
            return false;
        }
        try {
            Object proxy =
                    Proxy.newProxyInstance(
                            LISTENER_CLASS.getClassLoader(),
                            new Class<?>[] {LISTENER_CLASS},
                            new ListenerHandler());
            User.class.getMethod("addAuthenticationListener", LISTENER_CLASS).invoke(null, proxy);
            listener = proxy;
            return true;
        } catch (ReflectiveOperationException e) {
            LOGGER.warn("Failed to register the authentication listener:", e);
            return false;
        }
    }

    private void unregister() {
        if (listener == null) {
            return;
        }
        try {
            User.class
                    .getMethod("removeAuthenticationListener", LISTENER_CLASS)
                    .invoke(null, listener);
        } catch (ReflectiveOperationException e) {
            LOGGER.warn("Failed to remove the authentication listener:", e);
        }
        listener = null;
    }

    void onAuthenticationRequestSuccess(User user, HttpMessage trigger) {
        ContextState state = contexts.get(user.getContext().getName());
        if (state != null) {
            state.pending.remove(user.getName());
        }
    }

    void onAuthenticationRequestFailure(User user, HttpMessage trigger) {
        ContextState state = contexts.get(user.getContext().getName());
        if (state == null) {
            return;
        }

        Diagnostic diagnostic = state.pending.remove(user.getName());
        if (diagnostic == null) {
            return;
        }

        AuthenticationDiagnostics.persist(diagnostic, false);

        synchronized (state) {
            state.retainedIds.addLast(diagnostic.getId());
            while (state.retainedIds.size() > state.capacity) {
                AuthenticationDiagnostics.delete(state.retainedIds.pollFirst());
            }
        }
    }

    private class ListenerHandler implements InvocationHandler {

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            switch (method.getName()) {
                case "equals" -> {
                    // The core compares listeners when removing them.
                    return proxy == args[0];
                }
                case "onAuthenticationRequestSuccess" ->
                        onAuthenticationRequestSuccess((User) args[0], (HttpMessage) args[1]);
                case "onAuthenticationRequestFailure" ->
                        onAuthenticationRequestFailure((User) args[0], (HttpMessage) args[1]);
                default -> {
                    // Nothing to do.
                }
            }
            return null;
        }
    }

    /**
     * Per-context pending attempts, keyed by user name (a newer attempt for the same user replaces
     * the pending one), and ids of the retained failures.
     */
    private static final class ContextState {
        private final int capacity;
        private final boolean detailed;
        private final ConcurrentMap<String, Diagnostic> pending = new ConcurrentHashMap<>();
        private final Deque<Integer> retainedIds = new ArrayDeque<>();

        ContextState(int capacity, boolean detailed) {
            this.capacity = capacity;
            this.detailed = detailed;
        }
    }

    public enum Mode {
        AUTH_ON_FAILURE,
        AUTH_FAILURE_ROLLING;

        /**
         * @return the i18n'ed display name of this mode.
         */
        public String getName() {
            return Constant.messages.getString(
                    switch (this) {
                        case AUTH_ON_FAILURE ->
                                "authhelper.automation.diagnostics.mode.authonfailure";
                        case AUTH_FAILURE_ROLLING ->
                                "authhelper.automation.diagnostics.mode.authfailurerolling";
                    });
        }
    }
}
