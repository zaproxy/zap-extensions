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
package org.zaproxy.zap.extension.exportreport.FileChooser;

import java.io.File;
import java.util.Locale;
import javax.swing.ImageIcon;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.exportreport.Export.ExportReport;

/*
 * AUTHOR		:	GORAN SARENKAPA - JordanGS
 * SPONSOR		:	RYERSON UNIVERSITY
 */

public class Utils
{
	private static Logger logger = Logger.getLogger(ExportReport.class);
	
	public final static String	utf8					= "UTF-8";
	
	public final static String	dump					= ".dump.xml";
	
	private final static String	path					= "/org/zaproxy/zap/extension/exportreport/resources/images/";

	public final static String	html					= "xhtml";
	public final static String	htmlIcon				= path + "html.png";
	public final static String	htmlType				= "XHTML File";
	public final static String	htmlDescription			= "ASCII 1.0 Strict Compliant XHTML Files";

	public final static String	bootstrap				= "bootstrap.html";
	public final static String	bootstrapIcon			= path + "bootstrap.png";
	public final static String	bootstrapType			= "Bootstrap HTML File";
	public final static String	bootstrapDescription	= "Bootstrap HTML Files";

	public final static String	xml						= "xml";
	public final static String	xmlIcon					= path + "xml.png";
	public final static String	xmlType					= "XML File";
	public final static String	xmlDescription			= "XML Files";

	public final static String	json					= "json";
	public final static String	jsonIcon				= path + "json.png";
	public final static String	jsonType				= "JSON File";
	public final static String	jsonDescription			= "JSON Files";

	public final static String	pdf						= "pdf";
	public final static String	pdfIcon					= path + "pdf.png";
	public final static String	pdfType					= "PDF Document";
	public final static String	pdfDescription			= "PDF Documents";

	public final static String	doc						= "doc";
	public final static String	docIcon					= path + "doc.png";
	public final static String	docType					= "Google Document";
	public final static String	docDescription			= "Google Documents";

	public final static String	ALL						= "ALL";

	/*
	 * Get the extension of a file.
	 */
	public static String getExtension(File f)
	{
		String ext = null;
		String s = f.getName().toLowerCase(Locale.ROOT); // Use the locale rules
		int i = s.lastIndexOf('.');

		if (i > 0 && i < s.length() - 1)
		{
			if (s.contains(bootstrap))
			{
				String temp = s.substring(0, s.lastIndexOf('.'));
				int j = temp.lastIndexOf('.');
				ext = s.substring(j + 1).toLowerCase(Locale.ROOT);
			}
			else
			{
				ext = s.substring(i + 1).toLowerCase(Locale.ROOT);
			}
		}
		return ext;
	}

	/** Returns an ImageIcon, or null if the path was invalid. */
	protected static ImageIcon createImageIcon(String path)
	{
		java.net.URL imgURL = Utils.class.getResource(path); // Might need ExtensionExportReport.class.getResource
		if (imgURL != null)
		{
			return new ImageIcon(imgURL);
		}
		else
		{
			logger.error(Constant.messages.getString("exportreport.message.error.file.image") + " " + path);
			return null;
		}
	}
}
