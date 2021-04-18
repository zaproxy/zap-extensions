/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.exim.har;

import edu.umass.cs.benchlab.har.HarContent;
import edu.umass.cs.benchlab.har.HarEntries;
import edu.umass.cs.benchlab.har.HarEntry;
import edu.umass.cs.benchlab.har.HarHeader;
import edu.umass.cs.benchlab.har.HarLog;
import edu.umass.cs.benchlab.har.HarResponse;
import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.utils.HarUtils;

public class HarImporter {

    public static List<HttpMessage> getHttpMessages(HarLog log)
            throws HttpMalformedHeaderException {
        List<HttpMessage> result = new ArrayList<HttpMessage>();
        HarEntries entries = log.getEntries();
        for (HarEntry entry : entries.getEntries()) {
            result.add(getHttpMessage(entry));
        }
        return result;
    }

    private static HttpMessage getHttpMessage(HarEntry harEntry)
            throws HttpMalformedHeaderException {
        HttpMessage result = HarUtils.createHttpMessage(harEntry.getRequest());
        setHttpResponse(harEntry.getResponse(), result);
        setHistoryReference(harEntry, result);
        return result;
    }

    private static void setHistoryReference(HarEntry harEntry, HttpMessage httpMessage) {
        if (harEntry.getCustomFields().getCustomFieldValue(HarUtils.MESSAGE_ID_CUSTOM_FIELD)
                == null) return;

        Integer historyId =
                Integer.valueOf(
                        harEntry.getCustomFields()
                                .getCustomFieldValue(HarUtils.MESSAGE_ID_CUSTOM_FIELD));
        try {
            httpMessage.setHistoryRef(new HistoryReference(historyId.intValue()));
        } catch (DatabaseException e) {
            /*no handler*/
        } catch (HttpMalformedHeaderException e) {
            /*no handler*/
        }
    }

    private static void setHttpResponse(HarResponse harResponse, HttpMessage message)
            throws HttpMalformedHeaderException {
        StringBuilder strBuilderResHeader = new StringBuilder();

        // empty responses without status code are possible
        if (harResponse.getStatus() == 0) return;

        strBuilderResHeader
                .append(harResponse.getHttpVersion())
                .append(' ')
                .append(harResponse.getStatus())
                .append(' ')
                .append(harResponse.getStatusText())
                .append("\r\n");

        for (HarHeader harHeader : harResponse.getHeaders().getHeaders()) {
            strBuilderResHeader
                    .append(harHeader.getName())
                    .append(": ")
                    .append(harHeader.getValue())
                    .append("\r\n");
        }
        strBuilderResHeader.append("\r\n");

        final HarContent harContent = harResponse.getContent();
        message.setResponseHeader(new HttpResponseHeader(strBuilderResHeader.toString()));
        if (harContent != null) message.setResponseBody(new HttpResponseBody(harContent.getText()));
    }
}
