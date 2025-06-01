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
package org.zaproxy.zap.extension.scripts.autocomplete;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.MenuElement;
import javax.swing.MenuSelectionManager;

@SuppressWarnings("serial")
public class ScriptAutoCompleteMenu extends JScrollPopupMenu {

    private static final long serialVersionUID = 1L;
    private ScriptAutoCompleteKeyListener parent;
    private List<JMenuItem> menus = new ArrayList<>();

    public ScriptAutoCompleteMenu(ScriptAutoCompleteKeyListener parent) {
        this.parent = parent;
        setFocusable(false);
    }

    private void selectMenu(int index) {
        menus.get(0).requestFocus();
        menus.get(0).requestFocusInWindow();
    }

    public void addMenu(final String text) {
        JMenuItem menu = new JMenuItem(text);
        menu.addActionListener(e -> parent.insertText(text));
        this.add(menu);
        menus.add(menu);
    }

    public void addMenu(Method method) {
        final JMenuItemMethod menu = new JMenuItemMethod(method);
        menu.addActionListener(
                e -> {
                    parent.insertText(menu.getText());
                    parent.setLastReturnType(menu.method.getReturnType());
                });
        this.add(menu);
        menus.add(menu);
    }

    public void selectFirstMenu() {
        if (this.menus.size() > 0) {
            MenuSelectionManager.defaultManager()
                    .setSelectedPath(new MenuElement[] {this, menus.get(0)});
            setFocusable(true);
            this.selectMenu(0);
        }
    }

    public void filterMenus(String txt) {
        String txtLc = txt.toLowerCase();
        for (JMenuItem menu : menus) {
            menu.setVisible(menu.getText().toLowerCase().startsWith(txtLc));
        }
        this.pack();
    }

    private static String methodSignature(Method method) {
        StringBuilder sb = new StringBuilder();
        sb.append(method.getName());
        sb.append('(');
        boolean first = true;
        for (Parameter param : method.getParameters()) {
            if (first) {
                first = false;
            } else {
                sb.append(", ");
            }
            sb.append(param.getName());
        }
        sb.append(')');
        return sb.toString();
    }

    private class JMenuItemMethod extends JMenuItem {

        private static final long serialVersionUID = 1L;
        private Method method;

        public JMenuItemMethod(Method method) {
            super(methodSignature(method));
            this.method = method;
        }
    }
}
