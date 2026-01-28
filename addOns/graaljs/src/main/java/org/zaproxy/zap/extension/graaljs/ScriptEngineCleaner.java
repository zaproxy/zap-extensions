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
package org.zaproxy.zap.extension.graaljs;

import com.oracle.truffle.js.scriptengine.GraalJSScriptEngine;
import java.io.Reader;
import java.lang.ref.Cleaner;
import java.util.concurrent.atomic.AtomicInteger;
import javax.script.Bindings;
import javax.script.Compilable;
import javax.script.CompiledScript;
import javax.script.Invocable;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import javax.script.ScriptException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class ScriptEngineCleaner implements ScriptEngine, Compilable, Invocable, AutoCloseable {

    private static final Logger LOGGER = LogManager.getLogger(ScriptEngineCleaner.class);

    private static final Cleaner CLEANER = Cleaner.create();

    private final GraalJSScriptEngine delegate;
    private final AtomicInteger counter;

    ScriptEngineCleaner(GraalJSScriptEngine delegate) {
        this.delegate = delegate;
        counter = new AtomicInteger();

        register(this);
    }

    private void register(Object object) {
        CLEANER.register(object, new CleanupAction(delegate, counter));
    }

    private <T> T track(T result) {
        if (isTrackable(result)) {
            register(result);
        }
        return result;
    }

    private static boolean isTrackable(Object object) {
        return object != null
                && !(object instanceof String
                        || object instanceof Number
                        || object instanceof Boolean
                        || object instanceof Character);
    }

    @Override
    public Object eval(String script, ScriptContext context) throws ScriptException {
        return track(delegate.eval(script, context));
    }

    @Override
    public Object eval(Reader reader, ScriptContext context) throws ScriptException {
        return track(delegate.eval(reader, context));
    }

    @Override
    public Object eval(String script) throws ScriptException {
        return track(delegate.eval(script));
    }

    @Override
    public Object eval(Reader reader) throws ScriptException {
        return track(delegate.eval(reader));
    }

    @Override
    public Object eval(String script, Bindings n) throws ScriptException {
        return track(delegate.eval(script, n));
    }

    @Override
    public Object eval(Reader reader, Bindings n) throws ScriptException {
        return track(delegate.eval(reader, n));
    }

    @Override
    public Object get(String key) {
        return track(delegate.get(key));
    }

    @Override
    public Object invokeMethod(Object thiz, String name, Object... args)
            throws ScriptException, NoSuchMethodException {
        return track(delegate.invokeMethod(thiz, name, args));
    }

    @Override
    public Object invokeFunction(String name, Object... args)
            throws ScriptException, NoSuchMethodException {
        return track(delegate.invokeFunction(name, args));
    }

    @Override
    public <T> T getInterface(Class<T> clasz) {
        return track(delegate.getInterface(clasz));
    }

    @Override
    public <T> T getInterface(Object thiz, Class<T> clasz) {
        return track(delegate.getInterface(thiz, clasz));
    }

    @Override
    public CompiledScript compile(String script) throws ScriptException {
        return track(delegate.compile(script));
    }

    @Override
    public CompiledScript compile(Reader script) throws ScriptException {
        return track(delegate.compile(script));
    }

    @Override
    public void put(String key, Object value) {
        delegate.put(key, value);
    }

    @Override
    public Bindings getBindings(int scope) {
        return delegate.getBindings(scope);
    }

    @Override
    public void setBindings(Bindings bindings, int scope) {
        delegate.setBindings(bindings, scope);
    }

    @Override
    public Bindings createBindings() {
        return delegate.createBindings();
    }

    @Override
    public ScriptContext getContext() {
        return delegate.getContext();
    }

    @Override
    public void setContext(ScriptContext context) {
        delegate.setContext(context);
    }

    @Override
    public ScriptEngineFactory getFactory() {
        return delegate.getFactory();
    }

    @Override
    public void close() {
        delegate.close();
    }

    private static class CleanupAction implements Runnable {

        private final GraalJSScriptEngine scriptEngine;
        private final AtomicInteger counter;

        CleanupAction(GraalJSScriptEngine scriptEngine, AtomicInteger counter) {
            this.scriptEngine = scriptEngine;
            this.counter = counter;
            this.counter.incrementAndGet();
        }

        @Override
        public void run() {
            counter.decrementAndGet();

            if (counter.compareAndSet(0, 0)) {
                try {
                    scriptEngine.close();
                } catch (Exception e) {
                    LOGGER.debug("Error closing engine:", e);
                }
            }
        }
    }
}
