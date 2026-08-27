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
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.text.JTextComponent;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.MenuWeights;
import org.zaproxy.addon.encoder.popup.EncoderOperationMenuItem;
import org.zaproxy.addon.encoder.popup.EncoderSubMenu;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessorItem;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessors;
import org.zaproxy.zap.extension.ExtensionPopupMenu;
import org.zaproxy.zap.view.popup.PopupMenuUtils;

/**
 * The "Encode/Decode/Hash..." right-click popup menu. Hovering shows the in-place Encode, Decode,
 * Hash, and Utility submenus. Clicking the menu opens the Encode/Decode/Hash dialog.
 */
@SuppressWarnings("serial")
public class PopupEncoderMenu extends ExtensionPopupMenu {

    private static final long serialVersionUID = 1L;

    private static final String[] ENCODE_IDS = {
        "base64encode",
        "base64urlencode",
        "urlencode",
        "fullurlencode",
        "hexencode",
        "htmlencode",
        "fullhtmlencode",
        "javascriptencode",
        "unicodeencode",
        "powershellencode",
        "morsecodeencode"
    };

    private static final String[] DECODE_IDS = {
        "base64decode",
        "base64urldecode",
        "urldecode",
        "fullurldecode",
        "hexdecode",
        "htmldecode",
        "javascriptdecode",
        "unicodedecode",
        "morsecodedecode"
    };

    private static final String[] HASH_IDS = {"md5hash", "sha1hash", "sha256hash"};

    private static final String[] UTILITY_IDS = {
        "removewhitespace",
        "reverse",
        "lowercase",
        "uppercase",
        "ascify",
        "illegalutf8with2byteencoder",
        "illegalutf8with3byteencoder",
        "illegalutf8with4byteencoder"
    };

    private volatile JTextComponent lastInvoker = null;

    public PopupEncoderMenu(Runnable dialogAction) {
        super(Constant.messages.getString("encoder.tools.menu.encdec"));
        setWeight(MenuWeights.MENU_ENCODE_WEIGHT);

        addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        dialogAction.run();
                    }
                });

        add(new EncoderSubMenu(msg("encoder.popup.menu.encode"), buildItems(ENCODE_IDS)));
        add(new EncoderSubMenu(msg("encoder.popup.menu.decode"), buildItems(DECODE_IDS)));
        add(new EncoderSubMenu(msg("encoder.popup.menu.hash"), buildItems(HASH_IDS)));
        add(new EncoderSubMenu(msg("encoder.popup.menu.utility"), buildItems(UTILITY_IDS)));
    }

    private static String msg(String key) {
        return Constant.messages.getString(key);
    }

    /**
     * @return Returns the lastInvoker.
     */
    public JTextComponent getLastInvoker() {
        return lastInvoker;
    }

    /**
     * @param lastInvoker The lastInvoker to set.
     */
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
            processExtensionPopupChildren(PopupMenuUtils.getPopupMenuInvokerWrapper(invoker));
            return true;
        }

        setLastInvoker(null);
        return false;
    }

    private static boolean isInvokerFromEncodeDecode(Component invoker) {
        if (invoker.getName() == null) {
            return false;
        }
        return invoker.getName().equals(EncodeDecodeDialog.ENCODE_DECODE_FIELD)
                || invoker.getName().equals(EncodeDecodeDialog.ENCODE_DECODE_RESULTFIELD);
    }

    @Override
    public int getWeight() {
        return MenuWeights.MENU_ENCODE_WEIGHT;
    }

    private static List<EncoderOperationMenuItem> buildItems(String[] processorIds) {
        List<EncoderOperationMenuItem> items = new ArrayList<>();
        for (String id : processorIds) {
            EncodeDecodeProcessorItem item =
                    EncodeDecodeProcessors.getPredefinedProcessors().stream()
                            .filter(
                                    p ->
                                            p.getId()
                                                    .equals(
                                                            EncodeDecodeProcessors.PREDEFINED_PREFIX
                                                                    + id))
                            .findFirst()
                            .orElse(null);
            if (item != null) {
                items.add(new EncoderOperationMenuItem(item.getName(), item.getProcessor()));
            }
        }
        return items;
    }
}
