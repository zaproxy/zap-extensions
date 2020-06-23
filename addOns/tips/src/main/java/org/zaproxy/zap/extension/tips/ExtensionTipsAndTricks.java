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
package org.zaproxy.zap.extension.tips;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.Set;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ZapMenuItem;

/*
 * An example ZAP extension which adds a top level menu item.
 *
 * This class is defines the extension.
 */
public class ExtensionTipsAndTricks extends ExtensionAdaptor {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionTipsAndTricks";

    private static final String PREFIX = "tips";
    private static final String TIPS_PREFIX = PREFIX + ".tip.";

    private ZapMenuItem menuTipsAndTricks = null;
    private TipsAndTricksDialog dialog = null;

    private List<String> tipsAndTricks = null;
    private Random random = new Random();

    public ExtensionTipsAndTricks() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addHelpMenuItem(getMenuTipsAndTricks());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    private ZapMenuItem getMenuTipsAndTricks() {
        if (menuTipsAndTricks == null) {
            menuTipsAndTricks = new ZapMenuItem(PREFIX + ".topmenu.help.tips");

            menuTipsAndTricks.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent ae) {
                            displayRandomTip();
                        }
                    });
        }
        return menuTipsAndTricks;
    }

    private List<String> getTipsAndTricks() {
        if (tipsAndTricks == null) {
            // Need to load them in
            tipsAndTricks = new ArrayList<String>();

            ResourceBundle rb = Constant.messages.getMessageBundle(PREFIX);
            Enumeration<String> enm = rb.getKeys();
            while (enm.hasMoreElements()) {
                String key = enm.nextElement();
                if (key.startsWith(TIPS_PREFIX)) {
                    tipsAndTricks.add(/*Constant.messages.getString(key)*/ rb.getString(key));
                }
            }

            if (tipsAndTricks.size() == 0) {
                this.getMenuTipsAndTricks().setEnabled(false);
            }
        }
        return this.tipsAndTricks;
    }

    public String getRandomTip() {
        return this.getTipsAndTricks().get(random.nextInt(this.getTipsAndTricks().size()));
    }

    private void displayRandomTip() {
        this.getTipsAndTricksDialog().displayTip();
    }

    private TipsAndTricksDialog getTipsAndTricksDialog() {
        if (dialog == null) {
            dialog = new TipsAndTricksDialog(this, View.getSingleton().getMainFrame());
        }
        return dialog;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    /**
     * Generate the help file including all of the tips
     *
     * @param parmas
     */
    public static void main(String[] parmas) {
        Properties props = new Properties();
        File f = new File("src/org/zaproxy/zap/extension/tips/resources/Messages.properties");
        try {
            props.load(new FileReader(f));

            File helpFile =
                    new File(
                            "src/org/zaproxy/zap/extension/tips/resources/help/contents/tips.html");
            FileWriter fw = new FileWriter(helpFile);

            fw.write("<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n");
            fw.write("<HTML>\n");
            fw.write("<HEAD>\n");
            fw.write("<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=utf-8\">\n");
            fw.write("<TITLE>\n");
            fw.write("Tips and Tricks\n");
            fw.write("</TITLE>\n");
            fw.write("</HEAD>\n");
            fw.write("<BODY BGCOLOR=\"#ffffff\">\n");
            fw.write("<H1>Tips and Tricks</H1>\n");
            fw.write("<!-- Note that this file is generated by ExtensionTipsAndTricks-->\n");
            fw.write(
                    "This add-on adds a 'help' menu item which displays useful ZAP tips and tricks.<br>\n");
            fw.write("Tips are also shown in the splash screen on start up.\n");
            fw.write("<H2>Full list of tips</H2>\n");

            Set<Object> keys = props.keySet();
            List<String> list = new ArrayList<String>();
            for (Object key : keys) {
                if (key.toString().startsWith(TIPS_PREFIX)) {
                    list.add(props.getProperty(key.toString()));
                }
            }
            Collections.sort(list);
            for (String tip : list) {
                fw.write("\n<p>" + tip.replace("\n", "<br>\n") + " </p>\n\n");
            }

            fw.write("</BODY>\n");
            fw.write("</HTML>\n");
            fw.close();

            System.out.println("Help file generated: " + helpFile.getAbsolutePath());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
