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
import org.zaproxy.addon.authhelper.internal.db.Diagnostic;
import org.zaproxy.addon.authhelper.internal.db.DiagnosticPersister;
import org.zaproxy.zap.users.User;

/**
 * Retention policy for authentication diagnostics collected during a scan, as configured
 * per-context by the {@code diagnostics} automation job's {@code auth_failure_rolling}/{@code
 * auth_on_failure} modes.
 *
 * <p>Multiple contexts (e.g. from concurrently running plans) can each have their own active
 * configuration at the same time, keyed by context name. Two concurrently running plans that happen
 * to use the same context name (e.g. both named "Default Context") share one configuration; the
 * later {@link #configure(String, Mode, int)} call replaces the earlier one. There's no plan
 * identity available at the point the core notifies outcomes, only the {@link User}, so isolation
 * is only as good as the context names are distinct.
 *
 * <p>While active for a context, it takes ownership of committing (or discarding) the diagnostics
 * that {@link AuthenticationDiagnostics#close()} would otherwise persist unconditionally:
 * successful attempts are dropped, failed attempts are persisted and, for the rolling mode, older
 * failures beyond the configured count are evicted.
 *
 * <p>TODO: core's {@code org.zaproxy.zap.users.AuthenticationListener}/{@code
 * User#addAuthenticationListener} (zaproxy/zaproxy#9465) is not yet in a released core, so the
 * listener is registered through reflection to keep compiling/working against today's release. Once
 * this add-on targets a core version that has the listener, remove {@link #listenerClass()}, {@link
 * #ensureRegistered()}, {@link #invoke(Object, Method, Object[])} and the {@code java.lang.reflect}
 * imports, implement {@code AuthenticationListener} directly and call {@code
 * User#addAuthenticationListener}/{@code removeAuthenticationListener} directly.
 */
public class AuthDiagnosticsPolicy implements InvocationHandler {

    private static final Logger LOGGER = LogManager.getLogger(AuthDiagnosticsPolicy.class);

    // XXX core dependency, see class javadoc.
    private static final String LISTENER_CLASS_NAME =
            "org.zaproxy.zap.users.AuthenticationListener";
    // XXX core dependency, see class javadoc.
    private static final String USER_CLASS_NAME = "org.zaproxy.zap.users.User";

    private static final AuthDiagnosticsPolicy INSTANCE = new AuthDiagnosticsPolicy();

    private final ConcurrentMap<String, ContextState> contexts = new ConcurrentHashMap<>();
    private Object listenerProxy;

    private AuthDiagnosticsPolicy() {}

    public static AuthDiagnosticsPolicy getInstance() {
        return INSTANCE;
    }

    // XXX reflection shim, see class javadoc.
    private static Class<?> listenerClass() {
        try {
            return Class.forName(LISTENER_CLASS_NAME);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    /**
     * Whether the running core supports per-attempt authentication notifications, required for this
     * policy to work.
     */
    public boolean isSupported() {
        return listenerClass() != null;
    }

    /**
     * Configures the policy to take over commit/discard decisions for authentications in the given
     * context, replacing any previous configuration for that context. Other contexts, if any, are
     * unaffected.
     *
     * <p>Callers should check {@link #isSupported()} first: if the core doesn't support
     * attempt-level notifications, the context is still marked active but nothing will ever call
     * back to commit or discard what {@link #defer(Diagnostic)} collects for it, leaking
     * diagnostics that are never persisted.
     *
     * @param context the name of the context the policy applies to.
     * @param mode the retention mode.
     * @param count the number of failures to retain, only relevant for {@link
     *     Mode#AUTH_FAILURE_ROLLING}.
     */
    public synchronized void configure(String context, Mode mode, int count) {
        ensureRegistered();
        int capacity = mode == Mode.AUTH_ON_FAILURE ? 1 : Math.max(1, count);
        contexts.put(context, new ContextState(capacity));
    }

    // XXX reflection shim, see class javadoc.
    private synchronized boolean ensureRegistered() {
        if (listenerProxy != null) {
            return true;
        }
        Class<?> listenerType = listenerClass();
        if (listenerType == null) {
            return false;
        }
        try {
            Object proxy =
                    Proxy.newProxyInstance(
                            listenerType.getClassLoader(), new Class<?>[] {listenerType}, this);
            Class.forName(USER_CLASS_NAME)
                    .getMethod("addAuthenticationListener", listenerType)
                    .invoke(null, proxy);
            listenerProxy = proxy;
            return true;
        } catch (ReflectiveOperationException e) {
            LOGGER.warn("Failed to register authentication listener:", e);
            return false;
        }
    }

    /**
     * Stops the policy applying to the given context. Removes the authentication listener once no
     * context is configured any more.
     *
     * @param context the name of the context to stop applying the policy to.
     */
    public synchronized void clear(String context) {
        contexts.remove(context);
        unregisterIfUnused();
    }

    /** Stops the policy applying to any context and removes the authentication listener. */
    public synchronized void clearAll() {
        contexts.clear();
        unregisterIfUnused();
    }

    // XXX reflection shim, see class javadoc.
    private void unregisterIfUnused() {
        if (listenerProxy == null || !contexts.isEmpty()) {
            return;
        }
        try {
            Class.forName(USER_CLASS_NAME)
                    .getMethod("removeAuthenticationListener", listenerClass())
                    .invoke(null, listenerProxy);
        } catch (ReflectiveOperationException e) {
            LOGGER.warn("Failed to remove authentication listener:", e);
        }
        listenerProxy = null;
    }

    /**
     * Whether the policy is currently active for the given context.
     *
     * @param context the name of the context to check, may be {@code null}.
     */
    public boolean isActive(String context) {
        return context != null && contexts.containsKey(context);
    }

    /**
     * Hands off a collected diagnostic to the policy instead of persisting it immediately; it will
     * be committed or discarded once the outcome of the authentication attempt is known. No-op if
     * the diagnostic's context is not configured.
     *
     * @param diagnostic the diagnostic collected for the attempt.
     */
    public void defer(Diagnostic diagnostic) {
        ContextState state = contexts.get(diagnostic.getContext());
        if (state != null) {
            state.pending.put(diagnostic.getUser(), diagnostic);
        }
    }

    // XXX reflection shim, see class javadoc: dispatches the proxied AuthenticationListener calls.
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) {
        switch (method.getName()) {
            case "onAuthenticationRequestSuccess":
                onAuthenticationRequestSuccess((User) args[0], (HttpMessage) args[1]);
                return null;
            case "onAuthenticationRequestFailure":
                onAuthenticationRequestFailure((User) args[0], (HttpMessage) args[1]);
                return null;
            case "hashCode":
                return System.identityHashCode(proxy);
            case "equals":
                return proxy == args[0];
            case "toString":
                return AuthDiagnosticsPolicy.class.getName();
            default:
                // onAuthenticationRequestStart, not used.
                return null;
        }
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

        if (DiagnosticPersister.persist(diagnostic, false)) {
            Thread.currentThread().interrupt();
        }

        synchronized (state) {
            state.retainedIds.addLast(diagnostic.getId());
            while (state.retainedIds.size() > state.capacity) {
                DiagnosticPersister.delete(state.retainedIds.pollFirst());
            }
        }
    }

    /**
     * Per-context pending attempts and retained failure ids.
     *
     * <p>{@code pending} is keyed by user name only: a second attempt for the same user that starts
     * before the first's outcome is known overwrites the pending diagnostic (last {@link
     * #defer(Diagnostic)} wins). Relies on {@code User.processMessageToMatchUser} serializing
     * re-authentication per user.
     */
    private static final class ContextState {
        private final int capacity;
        private final ConcurrentMap<String, Diagnostic> pending = new ConcurrentHashMap<>();
        private final Deque<Integer> retainedIds = new ArrayDeque<>();

        ContextState(int capacity) {
            this.capacity = capacity;
        }
    }

    public enum Mode {
        AUTH_ON_FAILURE,
        AUTH_FAILURE_ROLLING;

        /**
         * @return the i18n'ed display name of this mode.
         */
        public String getName() {
            switch (this) {
                case AUTH_ON_FAILURE:
                    return Constant.messages.getString(
                            "authhelper.automation.diagnostics.mode.authonfailure");
                case AUTH_FAILURE_ROLLING:
                    return Constant.messages.getString(
                            "authhelper.automation.diagnostics.mode.authfailurerolling");
                default:
                    return null;
            }
        }
    }
}
