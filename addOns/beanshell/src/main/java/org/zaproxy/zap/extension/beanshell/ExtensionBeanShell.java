/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Original code contributed by Stephen de Vries
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
package org.zaproxy.zap.extension.beanshell;

import java.awt.Dimension;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionBeanShell extends ExtensionAdaptor {

    private BeanShellConsoleFrame beanShellConsoleDialog = null;
    private ZapMenuItem menuBeanShell = null;

    /** */
    public ExtensionBeanShell() {
        super("ExtensionBeanShell");
        this.setOrder(38);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (getView() != null) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenuBeanShell());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (getView() != null) {
            if (beanShellConsoleDialog != null) {
                // TODO Stop BeanShell threads.
                // Background:
                // bsh.util.JConsole creates a thread when it is instantiated (in BeanShellPanel)
                // and bsh.Interpreter must be
                // run on a thread (in BeanShellConsoleFrame), those threads must be stopped here,
                // unfortunately BeanShell
                // doesn't provide a way to stop the threads. The threads will stay alive until ZAP
                // is closed.

                beanShellConsoleDialog.dispose();
                beanShellConsoleDialog = null;
            }
        }

        super.unload();
    }

    private ZapMenuItem getMenuBeanShell() {
        if (menuBeanShell == null) {
            menuBeanShell = new ZapMenuItem("beanshell.menu.title");
            menuBeanShell.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            BeanShellConsoleFrame dialog = getBeanShellConsoleDialog();
                            dialog.setVisible(true);
                        }
                    });
        }
        return menuBeanShell;
    }

    BeanShellConsoleFrame getBeanShellConsoleDialog() {
        if (beanShellConsoleDialog == null) {
            beanShellConsoleDialog =
                    new BeanShellConsoleFrame(getView().getMainFrame(), false, this);
            beanShellConsoleDialog.setView(getView());
            beanShellConsoleDialog.setPreferredSize(new Dimension(600, 600));
            beanShellConsoleDialog.setTitle(Constant.messages.getString("beanshell.title"));
        }
        return beanShellConsoleDialog;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("beanshell.desc");
    }
}
