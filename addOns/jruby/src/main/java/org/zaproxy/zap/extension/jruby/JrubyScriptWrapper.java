/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.jruby;

import java.io.File;
import java.io.IOException;
import java.io.Writer;
import javax.script.ScriptException;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class JrubyScriptWrapper extends ScriptWrapper {

    private final ScriptWrapper original;

    JrubyScriptWrapper(ScriptWrapper script) {
        this.original = script;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getInterface(Class<T> class1) throws ScriptException, IOException {
        // JRuby is a pain and doesnt seem to work like other JSR223 languages
        return (T) this.getEngine().getEngine().eval(this.getContents());
    }

    ScriptWrapper getOriginal() {
        return original;
    }

    @Override
    public String getName() {
        return original.getName();
    }

    @Override
    public void setName(String name) {
        this.original.setName(name);
    }

    @Override
    public String getDescription() {
        return original.getDescription();
    }

    @Override
    public void setDescription(String description) {
        this.original.setDescription(description);
    }

    @Override
    public ScriptEngineWrapper getEngine() {
        return original.getEngine();
    }

    @Override
    public void setEngine(ScriptEngineWrapper engine) {
        this.original.setEngine(engine);
    }

    @Override
    public void setEngineName(String engineName) {
        this.original.setEngineName(engineName);
    }

    @Override
    public String getEngineName() {
        return original.getEngineName();
    }

    @Override
    public ScriptType getType() {
        return original.getType();
    }

    @Override
    public void setType(ScriptType type) {
        this.original.setType(type);
    }

    @Override
    public String getTypeName() {
        return this.original.getTypeName();
    }

    @Override
    public String getContents() {
        return this.original.getContents();
    }

    @Override
    public void setContents(String contents) {
        this.original.setContents(contents);
    }

    @Override
    public String getLastOutput() {
        return original.getLastOutput();
    }

    @Override
    public void setLastOutput(String lastOutput) {
        original.setLastOutput(lastOutput);
    }

    @Override
    public boolean isChanged() {
        return original.isChanged();
    }

    @Override
    public void setChanged(boolean changed) {
        this.original.setChanged(changed);
    }

    @Override
    public boolean isEnabled() {
        return original.isEnabled();
    }

    @Override
    public void setEnabled(boolean enabled) {
        original.setEnabled(enabled);
    }

    @Override
    public String getLastErrorDetails() {
        return original.getLastErrorDetails();
    }

    @Override
    public void setLastErrorDetails(String lastErrorDetails) {
        this.original.setLastErrorDetails(lastErrorDetails);
    }

    @Override
    public Exception getLastException() {
        return original.getLastException();
    }

    @Override
    public void setLastException(Exception lastException) {
        this.original.setLastException(lastException);
    }

    @Override
    public boolean isError() {
        return original.isError();
    }

    @Override
    public void setError(boolean error) {
        this.original.setError(error);
    }

    @Override
    public boolean isLoadOnStart() {
        return original.isLoadOnStart();
    }

    @Override
    public void setLoadOnStart(boolean loadOnStart) {
        this.original.setLoadOnStart(loadOnStart);
    }

    @Override
    public File getFile() {
        return original.getFile();
    }

    @Override
    public void setFile(File file) {
        this.original.setFile(file);
    }

    @Override
    public Writer getWriter() {
        return original.getWriter();
    }

    @Override
    public void setWriter(Writer writer) {
        this.original.setWriter(writer);
    }
}
