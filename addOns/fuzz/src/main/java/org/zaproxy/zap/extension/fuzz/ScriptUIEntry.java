/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz;

import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ScriptUIEntry implements Comparable<ScriptUIEntry> {

    private final ScriptWrapper scriptWrapper;
    private final String scriptName;

    public ScriptUIEntry(ScriptWrapper scriptWrapper) {
        this.scriptWrapper = scriptWrapper;
        this.scriptName = scriptWrapper.getName();
        if (scriptName == null) {
            throw new IllegalArgumentException("Script must have a name.");
        }
    }

    public ScriptWrapper getScriptWrapper() {
        return scriptWrapper;
    }

    @Override
    public String toString() {
        return scriptName;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((scriptName == null) ? 0 : scriptName.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        ScriptUIEntry other = (ScriptUIEntry) obj;
        if (scriptName == null) {
            if (other.scriptName != null) {
                return false;
            }
        } else if (!scriptName.equals(other.scriptName)) {
            return false;
        }
        return true;
    }

    @Override
    public int compareTo(ScriptUIEntry other) {
        if (other == null) {
            return 1;
        }
        return scriptName.compareTo(other.scriptName);
    }
}
