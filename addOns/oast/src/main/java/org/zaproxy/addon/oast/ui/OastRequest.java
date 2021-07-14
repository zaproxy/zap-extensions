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
package org.zaproxy.addon.oast.ui;

import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.table.DefaultHistoryReferencesTableEntry;

public class OastRequest extends DefaultHistoryReferencesTableEntry {

    private String handler;
    private String referer;

    private OastRequest(HistoryReference historyReference) {
        super(historyReference, OastTableModel.COLUMNS);
    }

    public static OastRequest create(String handler, HttpMessage httpMessage)
            throws DatabaseException, HttpMalformedHeaderException {
        HistoryReference historyReference =
                new HistoryReference(
                        Model.getSingleton().getSession(), HistoryReference.TYPE_OAST, httpMessage);
        historyReference.addTag(handler);
        return create(historyReference);
    }

    public static OastRequest create(HistoryReference historyReference)
            throws DatabaseException, HttpMalformedHeaderException {
        OastRequest oastRequest = new OastRequest(historyReference);
        if (historyReference.getTags().size() > 0) {
            oastRequest.handler = historyReference.getTags().get(0);
        }
        oastRequest.referer =
                historyReference.getHttpMessage().getRequestHeader().getHeader(HttpHeader.REFERER);
        return oastRequest;
    }

    public String getHandler() {
        return handler;
    }

    public String getReferer() {
        return referer;
    }
}
