/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.addon.encoder;

import java.awt.Component;
import javax.swing.text.JTextComponent;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;

public class PopupEncoderMenu extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;
    private JTextComponent lastInvoker = null;

    public PopupEncoderMenu() {
        super(Constant.messages.getString("encoder.tools.menu.encdec"));
    }

    /** @return Returns the lastInvoker. */
    public JTextComponent getLastInvoker() {
        return lastInvoker;
    }

    /** @param lastInvoker The lastInvoker to set. */
    public void setLastInvoker(JTextComponent lastInvoker) {
        this.lastInvoker = lastInvoker;
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker instanceof JTextComponent && !isInvokerFromEncodeDecode(invoker)) {

            JTextComponent txt = (JTextComponent) invoker;
            String sel = txt.getSelectedText();
            this.setEnabled(!(sel == null || sel.length() == 0));

            setLastInvoker((JTextComponent) invoker);
            return true;
        }

        setLastInvoker(null);
        return false;
    }

    private boolean isInvokerFromEncodeDecode(Component invoker) {
        if (invoker.getName() == null) {
            return false;
        }

        return invoker.getName().equals(EncodeDecodeDialog.ENCODE_DECODE_FIELD)
                || invoker.getName().equals(EncodeDecodeDialog.ENCODE_DECODE_RESULTFIELD);
    }
}
