package org.zaproxy.zap.extension.exportReport.FileChooser;

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

import java.io.File;
import javax.swing.filechooser.*;

/*
 * AUTHOR		:	GORAN SARENKAPA - JordanGS
 * SPONSOR		:	RYERSON UNIVERSITY
 * CLASS		:	ReportFilter.java 
 * DESC			:	Filter class for FileChooser.
 * CREATED ON	:	MARCH 10TH, 2016
 * CURRENT VER	:	V1.0
 * SOURCE		:	https://github.com/JordanGS/workspace/tree/master/zap-extensions/src/org/zaproxy/zap/extension/exportReport
 */

/* 
 * MODIFED BY	:	<NAME> - <GIT USER>
 * MOD DATE		:	
 * MOD VERSION	:	<VERSION OF PLUGIN>
 * MOD DESC		:	
 */

public class ReportFilter extends FileFilter
{

	// Accept all directories and all specified files.
	private FileList	list;
	private String		search;

	public ReportFilter(FileList list, String search)
	{
		this.list = list;
		this.search = search;
	}

	// what files and folders are visible
	public boolean accept(File f)
	{
		if (f.isDirectory())
		{
			return true;
		}
		if (f.isFile())
		{
			String ext = Utils.getExtension(f);
			if (ext != null)
			{
				if (search != Utils.ALL)
				{
					if (ext.equalsIgnoreCase(list.getExtension(search)))
					{
						return true;
					}
					else
					{
						return false;
					}
				}
				else
				{
					boolean bool = false;
					for (int i = 0; i < list.size(); i++)
					{

						if (ext.equals(list.getExtension(i)))
						{
							bool = true;
						}
					}
					return bool;
				}
			}
		}
		return false;
	}

	// The description of this filter drop down list items
	public String getDescription()
	{
		String strExtension = "";
		if (search != Utils.ALL)
		{
			strExtension = String.format(" (*%s)", list.getExtension(search));
		}
		else
		{
			strExtension = "All (";
			for (int i = 0; i < list.size(); i++)
			{
				strExtension = strExtension + String.format("*%s", list.getExtension(i) + ", ");
			}
			strExtension = strExtension.substring(0, strExtension.length() - 2) + ")";
		}
		return list.getDescription(search) + strExtension;
	}

	public String getExtensionByDescription(String description)
	{
		return list.getExtensionByDescription(description);
	}
}
