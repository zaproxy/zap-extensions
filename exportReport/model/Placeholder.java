package org.zaproxy.zap.extension.exportReport.model;

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

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/*
 * AUTHOR		:	GORAN SARENKAPA - JordanGS
 * SPONSOR		:	RYERSON UNIVERSITY
 * CLASS		:	Placeholder.java 
 * DESC			:	JAXB class that is a placeholder for future addition.
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

@XmlType(name = "", propOrder =
{
		"name"
})
public class Placeholder
{
	private String	name;

	public String getName()
	{
		return name;
	}

	@XmlElement(name = "Name")
	public void setName(String name)
	{
		this.name = name;
	}
}