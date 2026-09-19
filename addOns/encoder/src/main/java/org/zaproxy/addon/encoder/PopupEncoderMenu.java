/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenu;
import javax.swing.text.JTextComponent;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.addon.commonlib.MenuWeights;
import org.zaproxy.addon.encoder.popup.EncoderOperationMenuItem;
import org.zaproxy.addon.encoder.processors.Category;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessorItem;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessors;
import org.zaproxy.zap.extension.ExtensionPopupMenu;
import org.zaproxy.zap.view.popup.PopupMenuUtils;

/**
 * The "Encode/Decode/Hash..." right-click popup menu. Hovering shows the in-place Encode, Decode,
 * Hash, and Utility submenus. The "Encode/Decode/Hash..." child item opens the Encode/Decode/Hash
 * dialog.
 */
@SuppressWarnings("serial")
public class PopupEncoderMenu extends ExtensionPopupMenu {

    private static final long serialVersionUID = 1L;

    private volatile JTextComponent lastInvoker = null;
    private final EncodeDecodeProcessors processors = new EncodeDecodeProcessors();
    private JMenu scriptsSubMenu;

    public PopupEncoderMenu(Runnable dialogAction) {
        super(Constant.messages.getString("encoder.tools.menu.encdec"));
        setWeight(MenuWeights.MENU_ENCODE_WEIGHT);

        ExtensionPopupMenuItem openDialogItem =
                new ExtensionPopupMenuItem(msg("encoder.popup.title")) {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public boolean isSafe() {
                        return true;
                    }

                    @Override
                    public boolean isEnableForComponent(Component invoker) {
                        return invoker instanceof JTextComponent
                                && !isInvokerFromEncodeDecode(invoker);
                    }
                };
        openDialogItem.addActionListener(e -> dialogAction.run());
        add(openDialogItem);

        for (Category category : Category.values()) {
            if (category == Category.SCRIPT) {
                continue;
            }
            List<EncoderOperationMenuItem> items = buildItems(processors, category);
            if (!items.isEmpty()) {
                add(newSubMenu(msg(category.getI18nKey()), items));
            }
        }
        rebuildScriptsMenu();
    }

    /**
     * Rebuilds the Scripts submenu from the current set of encode/decode scripts, so scripts added,
     * removed, or enabled/disabled since the menu was last shown are reflected.
     */
    private void rebuildScriptsMenu() {
        if (scriptsSubMenu != null) {
            remove(scriptsSubMenu);
            scriptsSubMenu = null;
        }

        List<EncoderOperationMenuItem> items = buildItems(processors, Category.SCRIPT);
        if (!items.isEmpty()) {
            scriptsSubMenu = newSubMenu(msg(Category.SCRIPT.getI18nKey()), items);
            add(scriptsSubMenu);
        }
    }

    private static JMenu newSubMenu(String label, List<EncoderOperationMenuItem> items) {
        JMenu menu = new JMenu(label);
        items.forEach(menu::add);
        return menu;
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
            EncoderOperationMenuItem.setCurrentInvoker((JTextComponent) invoker);
            rebuildScriptsMenu();
            processExtensionPopupChildren(PopupMenuUtils.getPopupMenuInvokerWrapper(invoker));
            return true;
        }

        setLastInvoker(null);
        EncoderOperationMenuItem.setCurrentInvoker(null);
        return false;
    }

    private static boolean isInvokerFromEncodeDecode(Component invoker) {
        return EncodeDecodeDialog.ENCODE_DECODE_FIELD.equals(invoker.getName())
                || EncodeDecodeDialog.ENCODE_DECODE_RESULTFIELD.equals(invoker.getName());
    }

    @Override
    public int getWeight() {
        return MenuWeights.MENU_ENCODE_WEIGHT;
    }

    private static List<EncoderOperationMenuItem> buildItems(
            EncodeDecodeProcessors processors, Category category) {
        List<EncoderOperationMenuItem> items = new ArrayList<>();
        for (EncodeDecodeProcessorItem item : processors.getItemsByCategory(category)) {
            EncoderOperationMenuItem menuItem =
                    new EncoderOperationMenuItem(item.getName(), item.getProcessor());
            menuItem.setEnabled(item.isEnabled());
            items.add(menuItem);
        }
        return items;
    }
}
