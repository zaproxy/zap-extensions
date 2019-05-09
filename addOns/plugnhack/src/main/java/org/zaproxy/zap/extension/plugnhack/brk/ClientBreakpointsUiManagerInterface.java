/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.plugnhack.brk;

import org.zaproxy.zap.extension.brk.BreakpointMessageInterface;
import org.zaproxy.zap.extension.brk.BreakpointsUiManagerInterface;
import org.zaproxy.zap.extension.brk.ExtensionBreak;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.plugnhack.ClientMessage;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;

public class ClientBreakpointsUiManagerInterface implements BreakpointsUiManagerInterface {

    private ClientBreakDialogAdd addDialog = null;
    private ClientBreakDialogEdit editDialog = null;

    private ExtensionPlugNHack extension;
    private ExtensionBreak extensionBreak;

    public ClientBreakpointsUiManagerInterface(
            ExtensionPlugNHack extension, ExtensionBreak extensionBreak) {
        this.extension = extension;
        this.extensionBreak = extensionBreak;
    }

    @Override
    public Class<ClientMessage> getMessageClass() {
        return ClientMessage.class;
    }

    @Override
    public Class<ClientBreakpointMessage> getBreakpointClass() {
        return ClientBreakpointMessage.class;
    }

    @Override
    public String getType() {
        return "Client";
    }

    @Override
    public void handleAddBreakpoint(Message aMessage) {
        showAddDialog(aMessage);
    }

    void addBreakpoint(ClientBreakpointMessage breakpoint) {
        extensionBreak.addBreakpoint(breakpoint);
    }

    @Override
    public void handleEditBreakpoint(BreakpointMessageInterface breakpoint) {
        showEditDialog((ClientBreakpointMessage) breakpoint);
    }

    void editBreakpoint(
            BreakpointMessageInterface oldBreakpoint, BreakpointMessageInterface newBreakpoint) {
        extensionBreak.editBreakpoint(oldBreakpoint, newBreakpoint);
    }

    @Override
    public void handleRemoveBreakpoint(BreakpointMessageInterface breakpoint) {
        extensionBreak.removeBreakpoint(breakpoint);
    }

    @Override
    public void reset() {}

    private void populateAddDialogAndSetVisible(Message aMessage) {
        addDialog.setMessage((ClientMessage) aMessage);
        addDialog.setVisible(true);
    }

    private void showAddDialog(Message aMessage) {
        if (addDialog == null) {
            addDialog = new ClientBreakDialogAdd(extension, this);
            populateAddDialogAndSetVisible(aMessage);
        } else if (!addDialog.isVisible()) {
            populateAddDialogAndSetVisible(aMessage);
        }
    }

    private void populateEditDialogAndSetVisible(ClientBreakpointMessage breakpoint) {
        editDialog.setBreakpoint(breakpoint);
        editDialog.setVisible(true);
    }

    private void showEditDialog(ClientBreakpointMessage breakpoint) {
        if (editDialog == null) {
            editDialog = new ClientBreakDialogEdit(extension, this);
            populateEditDialogAndSetVisible(breakpoint);
        } else if (!editDialog.isVisible()) {
            populateEditDialogAndSetVisible(breakpoint);
        }
    }
}
