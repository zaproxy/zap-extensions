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
import javax.swing.Icon;
import javax.swing.filechooser.*;

/*
 * AUTHOR		:	GORAN SARENKAPA - JordanGS
 * SPONSOR		:	RYERSON UNIVERSITY
 * CLASS		:	ReportFileView.java 
 * DESC			:	View class for FileChooser.
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

public class ReportFileView extends FileView
{
	FileList	list;

	public ReportFileView(FileList list)
	{
		this.list = list;
	}

	public String getName(File f)
	{
		return null; // let the L&F FileView figure this out
	}

	public String getDescription(File f)
	{
		return null; // let the L&F FileView figure this out
	}

	public Boolean isTraversable(File f)
	{
		return null; // let the L&F FileView figure this out
	}

	// Not currently used for anything but can be in future.
	public String getTypeDescription(File f)
	{
		String extension = Utils.getExtension(f);
		String type = null;
		if (extension != null)
		{
			for (int i = 0; i < list.size(); i++)
			{
				if (extension.equals(list.getExtension(i)))
				{
					type = list.getType(list.getSearch(i));
				}
			}
		}
		return type;
	}

	public Icon getIcon(File f)
	{
		String extension = Utils.getExtension(f);
		Icon icon = null;

		if (extension != null)
		{
			for (int i = 0; i < list.size(); i++)
			{
				if (extension.equals(list.getExtension(i)))
				{
					icon = list.getIcon(list.getSearch(i));
				}
			}
		}
		return icon;
	}
}
