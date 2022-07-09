/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.addon.exim;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.Stats;

public class PopupMenuSaveRawMessage extends AbstractPopupMenuSaveMessage {
    private static final long serialVersionUID = -7217818541206464572L;
    private static final Logger LOG = LogManager.getLogger(PopupMenuSaveRawMessage.class);
    private static final String STATS_RAW_FILE_MSG =
            ExtensionExim.STATS_PREFIX + "save.raw.file.msg";
    private static final String STATS_RAW_FILE_MSG_ERROR =
            ExtensionExim.STATS_PREFIX + "save.raw.file.msg.errors";
    private static final String MESSAGE_PREFIX = "exim.saveraw.";
    private static final String RAW_FILE_EXTENSION = ".raw";

    public PopupMenuSaveRawMessage() {
        super(MESSAGE_PREFIX, RAW_FILE_EXTENSION, PopupMenuSaveRawMessage::writeOutput);
    }

    private static void writeOutput(
            MessageComponent messageComponent, HttpMessage httpMessage, File file) {
        writeOutput(messageComponent, httpMessage, file, false);
    }

    private static void writeOutput(
            MessageComponent messageComponent, HttpMessage httpMessage, File file, boolean append) {
        boolean shouldAppend = append;
        byte[] bytes = new byte[0];

        byte[] bytesHeader;
        byte[] bytesBody;

        switch (messageComponent) {
            case ALL:
                writeOutput(MessageComponent.REQUEST, httpMessage, file);
                writeOutput(MessageComponent.RESPONSE, httpMessage, file, true);
                return;
            case REQUEST_HEADER:
                bytes = httpMessage.getRequestHeader().toString().getBytes();
                break;
            case REQUEST_BODY:
                bytes = httpMessage.getRequestBody().getBytes();
                break;
            case REQUEST:
                bytesHeader = httpMessage.getRequestHeader().toString().getBytes();
                bytesBody = httpMessage.getRequestBody().getBytes();
                bytes = new byte[bytesHeader.length + bytesBody.length];
                System.arraycopy(bytesHeader, 0, bytes, 0, bytesHeader.length);
                System.arraycopy(bytesBody, 0, bytes, bytesHeader.length, bytesBody.length);
                break;
            case RESPONSE_HEADER:
                bytes = httpMessage.getResponseHeader().toString().getBytes();
                break;
            case RESPONSE_BODY:
                bytes = httpMessage.getResponseBody().getBytes();
                break;
            case RESPONSE:
                bytesHeader = httpMessage.getResponseHeader().toString().getBytes();
                bytesBody = httpMessage.getResponseBody().getBytes();
                bytes = new byte[bytesHeader.length + bytesBody.length];
                System.arraycopy(bytesHeader, 0, bytes, 0, bytesHeader.length);
                System.arraycopy(bytesBody, 0, bytes, bytesHeader.length, bytesBody.length);
                break;
        }
        writeToFile(file, bytes, messageComponent, shouldAppend);
    }

    private static void writeToFile(
            File file, byte[] bytes, MessageComponent messageComponent, boolean append) {
        try (OutputStream fw = new BufferedOutputStream(new FileOutputStream(file, append))) {
            fw.write(bytes);
            Stats.incCounter(STATS_RAW_FILE_MSG + "." + messageComponent.name());
        } catch (IOException e) {
            View.getSingleton()
                    .showWarningDialog(
                            Constant.messages.getString(
                                    "exim.file.save.error", file.getAbsolutePath()));
            LOG.error(e.getMessage(), e);
            Stats.incCounter(STATS_RAW_FILE_MSG_ERROR + "." + messageComponent.name());
        }
    }
}
