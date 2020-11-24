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
package org.zaproxy.zap.extension.zest;

import java.io.IOException;
import javax.script.ScriptException;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zest.core.v1.ZestJSON;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestScript.Type;

public class ZestScriptWrapper extends ScriptWrapper {

    public static final String ZAP_BREAK_VARIABLE_NAME = "zap.break";
    public static final String ZAP_BREAK_VARIABLE_VALUE = "set";

    private boolean incStatusCodeAssertion = true;
    private boolean incLengthAssertion = true;
    private int lengthApprox = 1;
    private ZestScript zestScript = null;
    private ExtensionZest extension = null;
    private ScriptWrapper original = null;
    private boolean debug = false;
    private boolean recording = false;

    public ZestScriptWrapper(ScriptWrapper script) {
        this.original = script;
        zestScript = (ZestScript) ZestJSON.fromString(script.getContents());
        if (zestScript == null) {
            // new script
            zestScript = new ZestScript();
            Type ztype;
            switch (script.getType().getName()) {
                case ExtensionActiveScan.SCRIPT_TYPE_ACTIVE:
                case "sequence": // ExtensionSequence.TYPE_SEQUENCE
                    ztype = Type.Active;
                    break;
                case ExtensionPassiveScan.SCRIPT_TYPE_PASSIVE:
                    ztype = Type.Passive;
                    break;
                case ExtensionScript.TYPE_TARGETED:
                case ExtensionScript.TYPE_PROXY:
                    ztype = Type.Targeted;
                    break;
                case ExtensionScript.TYPE_STANDALONE:
                case ScriptBasedAuthenticationMethodType.SCRIPT_TYPE_AUTH:
                default:
                    ztype = Type.StandAlone;
                    break;
            }
            zestScript.setType(ztype);
            zestScript.setDescription(script.getDescription());
        }
        // Override the title in case its taken from a template
        zestScript.setTitle(script.getName());

        this.setName(script.getName());
        this.setDescription(script.getDescription());
        this.setEngine(script.getEngine());
        this.setEngineName(script.getEngineName());
        this.setType(script.getType());
        this.setEnabled(script.isEnabled());
        this.setFile(script.getFile());
        this.setLoadOnStart(script.isLoadOnStart());
        this.setChanged(script.isChanged());
    }

    public boolean isIncStatusCodeAssertion() {
        return incStatusCodeAssertion;
    }

    public void setIncStatusCodeAssertion(boolean incStatusCodeAssertion) {
        this.incStatusCodeAssertion = incStatusCodeAssertion;
    }

    public boolean isIncLengthAssertion() {
        return incLengthAssertion;
    }

    public void setIncLengthAssertion(boolean incLengthAssertion) {
        this.incLengthAssertion = incLengthAssertion;
    }

    public int getLengthApprox() {
        return lengthApprox;
    }

    public void setLengthApprox(int lengthApprox) {
        this.lengthApprox = lengthApprox;
    }

    public ZestScript getZestScript() {
        return zestScript;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getInterface(Class<T> class1) throws ScriptException, IOException {
        // Clone the wrapper so that we get a new instance every time
        if (class1.isAssignableFrom(ZestPassiveRunner.class)) {
            return (T) new ZestPassiveRunner(this.getExtension(), this.clone());

        } else if (class1.isAssignableFrom(ZestActiveRunner.class)) {
            return (T) new ZestActiveRunner(this.getExtension(), this.clone());

        } else if (class1.isAssignableFrom(ZestTargetedRunner.class)) {
            return (T) new ZestTargetedRunner(this.getExtension(), this.clone());

        } else if (class1.isAssignableFrom(ZestHttpSenderRunner.class)) {
            return (T) new ZestHttpSenderRunner(this.getExtension(), this.clone());

        } else if (class1.isAssignableFrom(ZestProxyRunner.class)) {
            return (T) new ZestProxyRunner(this.getExtension(), this.clone());

        } else if (class1.isAssignableFrom(ZestAuthenticationRunner.class)) {
            return (T) new ZestAuthenticationRunner(this.getExtension(), this.clone());
        } else if (class1.isAssignableFrom(ZestSequenceRunner.class)) {
            return (T) new ZestSequenceRunner(this.getExtension(), this.clone());
        }
        return null;
    }

    private ExtensionZest getExtension() {
        if (extension == null) {
            extension =
                    (ExtensionZest)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionZest.NAME);
        }
        return extension;
    }

    @Override
    protected ZestScriptWrapper clone() {
        this.original.setContents(this.getContents());
        ZestScriptWrapper clone = new ZestScriptWrapper(this.original);
        clone.setWriter(this.getWriter());
        clone.setDebug(this.isDebug());
        clone.setRecording(this.isRecording());
        return clone;
    }

    @Override
    public String getContents() {
        return ZestJSON.toString(this.zestScript);
    }

    @Override
    public void setContents(String script) {
        // Do nothing - its all handled elsewhere
    }

    @Override
    public int hashCode() {
        return original.hashCode();
    }

    @Override
    public boolean equals(Object script) {
        return super.equals(script) || this.original.equals(script);
    }

    public boolean isDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    public boolean isRecording() {
        return recording;
    }

    public void setRecording(boolean recording) {
        this.recording = recording;
    }

    @Override
    public boolean isRunableStandalone() {
        // We can always prompt for parameters :)
        return true;
    }

    ScriptWrapper getOriginal() {
        return original;
    }
}
