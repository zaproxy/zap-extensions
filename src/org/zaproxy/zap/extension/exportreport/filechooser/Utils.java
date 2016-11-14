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
package org.zaproxy.zap.extension.exportreport.filechooser;

import java.io.File;
import java.util.Locale;

import javax.swing.ImageIcon;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

public class Utils {
    private static final Logger logger = Logger.getLogger(Utils.class);

    public static final String DUMP = ".dump.xml";

    private static final String PATH = "/org/zaproxy/zap/extension/exportreport/resources/images/";

    public static final String HTML = "xhtml";
    public static final String HTML_ICON = PATH + "html.png";
    public static final String HTML_TYPE = Constant.messages.getString("exportreport.utils.xhtml.type");
    public static final String HTML_DESCRIPTION = Constant.messages.getString("exportreport.utils.xhtml.desc");

    public static final String BOOTSTRAP = "bootstrap.html";
    public static final String BOOTSTRAP_ICON = PATH + "bootstrap.png";
    public static final String BOOTSTRAP_TYPE = Constant.messages.getString("exportreport.utils.bootstrap.type");
    public static final String BOOTSTRAP_DESCRIPTION = Constant.messages.getString("exportreport.utils.bootstrap.desc");

    public static final String XML = "xml";
    public static final String XML_ICON = PATH + "xml.png";
    public static final String XML_TYPE = Constant.messages.getString("exportreport.utils.xml.type");
    public static final String XML_DESCRIPTION = Constant.messages.getString("exportreport.utils.xml.desc");

    public static final String JSON = "json";
    public static final String JSON_ICON = PATH + "json.png";
    public static final String JSON_TYPE = Constant.messages.getString("exportreport.utils.json.type");
    public static final String JSON_DESCRIPTION = Constant.messages.getString("exportreport.utils.json.desc");

    public static final String PDF = "pdf";
    public static final String PDF_ICON = PATH + "pdf.png";
    public static final String PDF_TYPE = Constant.messages.getString("exportreport.utils.pdf.type");
    public static final String PDF_DESCRIPTION = Constant.messages.getString("exportreport.utils.pdf.desc");

    public static final String DOC = "doc";
    public static final String DOC_ICON = PATH + "doc.png";
    public static final String DOC_TYPE = Constant.messages.getString("exportreport.utils.doc.type");
    public static final String DOC_DESCRIPTION = Constant.messages.getString("exportreport.utils.doc.desc");

    public static final String ALL = "ALL";

    /*
     * Get the extension of a file.
     */
    public static String getExtension(File f) {
        String ext = null;
        String s = f.getName().toLowerCase(Locale.ROOT); // Use the locale rules
        int i = s.lastIndexOf('.');

        if (i > 0 && i < s.length() - 1) {
            if (s.contains(BOOTSTRAP)) {
                String temp = s.substring(0, s.lastIndexOf('.'));
                int j = temp.lastIndexOf('.');
                ext = s.substring(j + 1).toLowerCase(Locale.ROOT);
            } else {
                ext = s.substring(i + 1).toLowerCase(Locale.ROOT);
            }
        }
        return ext;
    }

    /** Returns an ImageIcon, or null if the path was invalid. */
    protected static ImageIcon createImageIcon(String path) {
        java.net.URL imgURL = Utils.class.getResource(path); // Might need ExtensionExportReport.class.getResource
        if (imgURL != null) {
            return new ImageIcon(imgURL);
        } else {
            logger.error(Constant.messages.getString("exportreport.message.error.file.image") + " " + path);
            return null;
        }
    }
}
