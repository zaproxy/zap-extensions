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

import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class ZestResultWrapper extends HistoryReference {

    public enum Type {
        request,
        scanAction
    }

    private boolean passed = false;
    private String message = "";
    private int scriptRequestIndex = -1;
    private Type type = Type.request;

    public ZestResultWrapper(
            Session session, int historyType, HttpMessage msg, int scriptRequestIndex)
            throws HttpMalformedHeaderException, DatabaseException {
        super(session, historyType, msg);
        this.scriptRequestIndex = scriptRequestIndex;
    }

    public boolean isPassed() {
        return passed;
    }

    public void setPassed(boolean passed) {
        this.passed = passed;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public int getScriptRequestIndex() {
        return scriptRequestIndex;
    }

    public void setScriptRequestIndex(int scriptRequestIndex) {
        this.scriptRequestIndex = scriptRequestIndex;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }
}
