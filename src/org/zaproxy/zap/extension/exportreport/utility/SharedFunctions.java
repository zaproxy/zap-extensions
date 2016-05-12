/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * This file is based on the Paros code file ReportLastScan.java
 */
package org.zaproxy.zap.extension.exportreport.utility;

import java.awt.Dimension;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.Image;
import java.awt.font.TextAttribute;
import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFormattedTextField;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpringLayout;
import javax.swing.UIManager;

import org.apache.log4j.Logger;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

public class SharedFunctions {
    private static final Logger logger = Logger.getLogger(SharedFunctions.class);

    private static String DEFAULT_FONT = "";
    private static boolean EXISTS_FONT = false;

    public final static String DATE_FORMAT = "EEE, d MMM yyyy HH:mm:ss z(Z)";

    public static String getCurrentTimeStamp() {
        SimpleDateFormat date = new SimpleDateFormat(DATE_FORMAT);
        Date now = new Date();
        String strDate = date.format(now);
        // System.out.println(strDate);
        return strDate;
    }

    public static boolean fontExists(String name) {
        GraphicsEnvironment g = null;
        g = GraphicsEnvironment.getLocalGraphicsEnvironment();
        String[] fonts = g.getAvailableFontFamilyNames();
        for (int i = 0; i < fonts.length; i++) {
            // System.out.println(fonts[i]);
            if (fonts[i].equals(name)) {
                setDefaultFont(name);
                setExistsFont(true);
                return true;
            }
        }
        return false;
    }

    public static void setDefaultFont(String name) {
        DEFAULT_FONT = name;
    }

    public static void setExistsFont(boolean bool) {
        EXISTS_FONT = bool;
    }

    public static String getDefaultFont() {
        return DEFAULT_FONT;
    }

    public static boolean getExistsFont() {
        return EXISTS_FONT;
    }

    public static Font getTitleFont() {
        Map<TextAttribute, Integer> fontAttributes = new HashMap<TextAttribute, Integer>();
        fontAttributes.put(TextAttribute.UNDERLINE, TextAttribute.UNDERLINE_ON);
        String name = UIManager.getDefaults().getFont("Label.font").getFamily();
        if (getExistsFont())
            name = getDefaultFont();
        // System.out.println(name);
        return new Font(name, Font.BOLD, 30).deriveFont(fontAttributes);
    }

    public static Font getLabelFont() {
        String name = UIManager.getDefaults().getFont("Label.font").getFamily();
        if (getExistsFont())
            name = getDefaultFont();
        // System.out.println(name);
        return new Font(name, Font.BOLD, 14);
    }

    public static void allignLabelTop(JLabel lbl) {
        lbl.setVerticalAlignment(JLabel.TOP);
        lbl.setVerticalTextPosition(JLabel.TOP);
        lbl.setBorder(BorderFactory.createEmptyBorder(3 /* top */, 0, 0, 0));
    }

    public static void createLabel(JPanel pnl, String str, Font font) {
        JLabel lbl = new JLabel(str, JLabel.TRAILING);
        lbl.setFont(font);
        pnl.add(lbl);
    }

    public static JButton createImageButton(String strImg) {
        JButton btn = new JButton();
        Image img = null;
        try {
            img = ImageIO.read(new File(strImg));
        } catch (IOException e) {
            logger.error(e.getMessage(), e);
        }
        btn.setIcon(new ImageIcon(img));
        btn.setPreferredSize(new Dimension(20, 20));
        return btn;
    }

    public static JFormattedTextField createDateField(JPanel pnl, String str, String tip) {
        SimpleDateFormat format = new SimpleDateFormat(DATE_FORMAT);
        JFormattedTextField txt = new JFormattedTextField(format);
        txt.setText(str);
        txt.setToolTipText(tip);
        pnl.add(txt);
        return txt;
    }

    public static JTextField createTextField(JPanel pnl, String str, String tip, Boolean bool, int limit) {
        JTextField txt = new JTextField();
        if (limit > -1) {
            txt.setDocument(new JTextFieldLimit(limit));
        }
        txt.setText(str);
        txt.setEditable(bool);
        txt.setToolTipText(tip);
        pnl.add(txt);
        return txt;
    }

    public static JTextArea createTextArea(int rows, int cols, String tip, int limit) {
        JTextArea txt = new JTextArea(rows, cols);
        if (limit > -1) {
            txt.setDocument(new JTextFieldLimit(limit));
        }
        txt.setToolTipText(tip);
        txt.setLineWrap(true);
        txt.setWrapStyleWord(true);
        return txt;
    }

    public static JComboBox<Object> createComboBox(JPanel pnl, ArrayList<String> list) {
        JComboBox<Object> typeList = new JComboBox<>(list.toArray());
        typeList.setSelectedIndex(0);
        pnl.add(typeList);
        return typeList;
    }

    public static String[] appendToArray(ArrayList<String> list, int count, int max) {
        count++;
        String[] compile = new String[list.size()];
        for (int i = 0; i < compile.length; i++) {
            String temp = Integer.toString(count);
            for (int j = temp.length(); j < (Integer.toString(max)).length(); j++) {
                compile[i] = ((compile[i] == null) ? "0" : compile[i] + "0");
            }
            compile[i] = ((compile[i] == null) ? count + ". " + list.get(i) : compile[i] + count + ". " + list.get(i));
            count++;
        }
        return compile;

    }

    public static SpringLayout setupConstraints(SpringLayout sl, JPanel content, JPanel container, int[] pad) {
        sl.putConstraint(SpringLayout.NORTH, content, pad[0], SpringLayout.NORTH, container);
        sl.putConstraint(SpringLayout.WEST, content, pad[1], SpringLayout.WEST, container);
        sl.putConstraint(SpringLayout.SOUTH, content, pad[2], SpringLayout.NORTH, container);
        sl.putConstraint(SpringLayout.EAST, content, pad[3], SpringLayout.WEST, container);
        return sl;
    }
}