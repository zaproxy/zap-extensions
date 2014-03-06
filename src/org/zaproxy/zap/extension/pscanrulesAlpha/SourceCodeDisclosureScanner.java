/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
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
 */
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.htmlparser.jericho.Source;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;


/**
 * A class to passively scan response for application Source Code, using source code signatures
 * @author 70pointer@gmail.com
 *
 */
public class SourceCodeDisclosureScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;
	
	/**
	 * a map of a regular expression pattern to the Programming language to which the pattern most likely corresponds
	 */
	static Map <Pattern, String> languagePatterns = new HashMap <Pattern, String> ();
	
	static {
		//PHP
		languagePatterns.put(Pattern.compile("<\\?php\\s*.+?;\\s*\\?>", Pattern.MULTILINE | Pattern.DOTALL), "PHP");
		languagePatterns.put(Pattern.compile("phpinfo\\s*\\(\\s*\\)"), "PHP");
		languagePatterns.put(Pattern.compile("\\$_POST\\s*\\["), "PHP");
		languagePatterns.put(Pattern.compile("\\$_GET\\s*\\["), "PHP");
		
		//JSP (Java based)
		languagePatterns.put(Pattern.compile("<%@\\s*page\\s+.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "JSP");
		languagePatterns.put(Pattern.compile("<%@\\s*include.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "JSP");
		languagePatterns.put(Pattern.compile("<%@\\s*taglib.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "JSP");
		languagePatterns.put(Pattern.compile("<jsp:directive\\.page.+?>", Pattern.MULTILINE | Pattern.DOTALL), "JSP");
		languagePatterns.put(Pattern.compile("<jsp:directive\\.include.+?>", Pattern.MULTILINE | Pattern.DOTALL), "JSP");
		languagePatterns.put(Pattern.compile("<jsp:directive\\.taglib.+?>", Pattern.MULTILINE | Pattern.DOTALL), "JSP");
		
		//Servlet (Java based)
		languagePatterns.put(Pattern.compile("import\\s+javax\\.servlet\\.http\\.HttpServlet\\s*;"), "Servlet");
		languagePatterns.put(Pattern.compile("import\\s+javax\\.servlet\\.http\\.\\*\\s*;"), "Servlet");
		languagePatterns.put(Pattern.compile("@WebServlet\\s*\\(\\s*\"/[a-z0-9]+\"\\s*\\)", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE), "Servlet");
		languagePatterns.put(Pattern.compile("public\\s+class\\s+[a-z0-9]+\\s+extends\\s+(javax\\.servlet\\.http\\.)?HttpServlet", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE), "Servlet");
		languagePatterns.put(Pattern.compile("public\\s+void\\s+doGet\\s*\\(\\s*HttpServletRequest\\s+[a-z0-9]+\\s*,\\s*HttpServletResponse\\s+[a-z0-9]+\\s*\\)", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE), "Servlet");
		languagePatterns.put(Pattern.compile("public\\s+void\\s+doPost\\s*\\(\\s*HttpServletRequest\\s+[a-z0-9]+\\s*,\\s*HttpServletResponse\\s+[a-z0-9]+\\s*\\)", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE), "Servlet");
		
		//Java
		languagePatterns.put(Pattern.compile("^package\\s+[a-z0-9.]+;", Pattern.CASE_INSENSITIVE), "Java");
		languagePatterns.put(Pattern.compile("^import\\s+[a-z0-9.]+;", Pattern.CASE_INSENSITIVE), "Java");
		languagePatterns.put(Pattern.compile("class\\s+[a-z0-9]+\\s*\\{.+\\}", Pattern.MULTILINE | Pattern.DOTALL ), "Java");
		languagePatterns.put(Pattern.compile("public\\s+static\\s+void\\s+main\\s*\\(\\s*String\\s+[a-z0-9]+\\s*\\[\\s*\\]\\s*\\)\\s*\\{", Pattern.MULTILINE | Pattern.DOTALL), "Java");
		languagePatterns.put(Pattern.compile("public\\s+static\\s+void\\s+main\\s*\\(\\s*String\\s*\\[\\s*\\]\\s*[a-z0-9]+\\s*\\)\\s*\\{", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE), "Java");

		//ASP
		languagePatterns.put(Pattern.compile("On\\s*Error\\s*Resume\\s*Next", Pattern.CASE_INSENSITIVE), "ASP");
		languagePatterns.put(Pattern.compile("Server.CreateObject\\s*\\(\\s*\"[a-z0-9.]+\"\\s*\\)", Pattern.CASE_INSENSITIVE), "ASP");
		languagePatterns.put(Pattern.compile("Request.QueryString\\s*\\(\\s*\"[a-z0-9]+\"\\s*\\)", Pattern.CASE_INSENSITIVE), "ASP");
		languagePatterns.put(Pattern.compile("If\\s*\\(\\s*Err.Number\\s*.+\\)\\s*Then", Pattern.CASE_INSENSITIVE), "ASP");
		languagePatterns.put(Pattern.compile("<%@\\s+LANGUAGE\\s*=\\s*\"VBSCRIPT\"\\s*%>", Pattern.CASE_INSENSITIVE), "ASP");
		
		//ASP.NET
		languagePatterns.put(Pattern.compile("<%@\\s+Page.*?%>", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("<script\\s+runat\\s*=\\s*\"", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("<%Assembly.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("<%Control.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("<%Implements.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("<%MasterType.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("<%Master.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");		
		languagePatterns.put(Pattern.compile("<%Page.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("<%OutputCache.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("<%PreviousPageType.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("<%Reference.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("<%Register.+?%>", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("@RenderPage\\s*\\(\\s*\".*?\"\\)", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("@RenderBody\\s*\\(\\s*\\)", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("@RenderSection\\s*\\(\\s*\".+?\"\\s*\\)", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		//languagePatterns.put(Pattern.compile("@\\{[\\u0000-\\u007F]{5,}?\\}", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");  //Too many false positives
		languagePatterns.put(Pattern.compile("@if\\s*\\(.+?\\)\\s*\\{", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("Request\\s*\\[\".+?\"\\]", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("@foreach\\s*", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("Database.Open\\s*\\(\\s*\"", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("db.Query\\s*\\(\\s*\"", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");		
		languagePatterns.put(Pattern.compile("@switch\\s*\\(.+?\\)\\s*\\{", Pattern.MULTILINE | Pattern.DOTALL), "ASP.NET");
		languagePatterns.put(Pattern.compile("^\\s*<asp:Menu"), "ASP.NET");
		languagePatterns.put(Pattern.compile("^\\s*<asp:TreeView"), "ASP.NET");
		languagePatterns.put(Pattern.compile("^\\s*<asp:SiteMapPath"), "ASP.NET");
		
		//C#
		languagePatterns.put(Pattern.compile("^<%@\\s+Page\\s+Language\\s*=\\s*\"C#\""), "C#");
		languagePatterns.put(Pattern.compile("^using\\s+System\\s*;"), "C#");
		languagePatterns.put(Pattern.compile("^namespace\\s+[a-z.]+\\s*\\{", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "C#");
		languagePatterns.put(Pattern.compile("^static\\s+void\\s+Main\\s*\\(\\s*string\\s*\\[\\s*\\]\\s*[a-z0-9]+\\s*\\)", Pattern.MULTILINE ), "C#");
		//generates false positives for JavaScript code, which also uses "var" to declare variables. 
		//languagePatterns.put(Pattern.compile("var\\s+[a-z]+?\\s*=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL), "C#");
		languagePatterns.put(Pattern.compile("@for\\s*\\(\\s*var\\s+", Pattern.MULTILINE | Pattern.DOTALL), "C#");
		languagePatterns.put(Pattern.compile("@foreach\\s*\\(\\s*var\\s+", Pattern.MULTILINE | Pattern.DOTALL), "C#");
		
		//VB.NET
		languagePatterns.put(Pattern.compile("^Imports\\s+System[a-zA-Z0-9.]*\\s*$"), "VB.NET");
		languagePatterns.put(Pattern.compile("^dim\\s+[a-z0-9]+\\s*=", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "VB.NET");
		languagePatterns.put(Pattern.compile("@for\\s+[a-z0-9]+\\s*=\\s*[0-9]+\\s+to\\s+[0-9]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "VB.NET");
		languagePatterns.put(Pattern.compile("@for\\s+each\\s+[a-z0-9]+\\s+in\\s+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "VB.NET");
		languagePatterns.put(Pattern.compile("@Select\\s+Case", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "VB.NET");
		languagePatterns.put(Pattern.compile("end\\s+select", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "VB.NET");

		
		//SQL (ie, generic Structured Query Language, not "Microsoft SQL Server", which some incorrectly refer to as just "SQL")  
		languagePatterns.put(Pattern.compile("select\\s+.+?\\s+from\\s+[a-z0-9.]+\\s+where\\s+", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("select\\s+@@[a-z]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("insert\\s+into\\s+[a-z0-9._]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("insert\\s+[a-z0-9._]+\\s+\\(.+?\\)\\s+values\\s*\\(.+?\\)", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("insert\\s+[a-z0-9._]+\\s+values\\s*\\(.+?\\)", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("insert\\s+[a-z0-9._]+\\s+select\\s+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("update\\s+[a-z0-9._]+\\s+set\\s+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("update\\s+[a-z0-9._]+\\s+[a-z0-9_]+\\s+set\\s+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language"); //allow a table alias
		languagePatterns.put(Pattern.compile("delete\\s+from\\s+[a-z0-9._]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		//causes false positives on normal JavaScript: delete B.fn;
		//languagePatterns.put(Pattern.compile("delete\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("truncate\\s+table\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("create\\s+database\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("create\\s+table\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("create\\s+view\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("create\\s+index\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("create\\s+procedure\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("create\\s+function\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");		
		languagePatterns.put(Pattern.compile("drop\\s+database\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("drop\\s+table\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("drop\\s+view\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("drop\\s+index\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("drop\\s+procedure\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("drop\\s+function\\s+[a-z0-9.]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("grant\\s+[a-z]+\\s+on\\s+[a-z0-9._]+\\s+to\\s+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
		languagePatterns.put(Pattern.compile("revoke\\s+[a-z]+", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Structured Query Language");
				
		//Perl
		languagePatterns.put(Pattern.compile("^#!/usr/bin/perl"), "Perl");
		languagePatterns.put(Pattern.compile("^use\\s+strict\\s*;\\s*$"), "Perl");
		languagePatterns.put(Pattern.compile("^use\\s+warnings\\s*;\\s*$"), "Perl");
		languagePatterns.put(Pattern.compile("^use\\s+[A-Za-z:]+\\s*;\\s*$"), "Perl");
		languagePatterns.put(Pattern.compile("foreach\\s+my\\s+\\$[a-z0-9]+\\s*\\(", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Perl");
		//languagePatterns.put(Pattern.compile("next unless"), "Perl");
		languagePatterns.put(Pattern.compile("^\\s*my\\s+\\$[a-z0-9]+\\s*", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Perl");
		languagePatterns.put(Pattern.compile("^\\s*my\\s+%[a-z0-9]+\\s*", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Perl");
		languagePatterns.put(Pattern.compile("^\\s*my\\s+@[a-z0-9]+\\s*", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Perl");		
		languagePatterns.put(Pattern.compile("@[a-z0-9]+\\s+[a-z0-9]+\\s*=\\s*\\(", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Perl");		
		languagePatterns.put(Pattern.compile("\\$#[a-z0-9]{4,}", Pattern.CASE_INSENSITIVE), "Perl"); 
		languagePatterns.put(Pattern.compile("\\$[a-z0-9]+\\s*\\{'[a-z0-9]+'\\}\\s*=\\s*", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Perl");
		languagePatterns.put(Pattern.compile("die\\s+\".*?\\$!.*?\""), "Perl");
		
		//Objective C (probably an iPhone app)
		languagePatterns.put(Pattern.compile("^#\\s+import\\s+<[a-zA-Z0-9/.]+>"), "Objective C");
		languagePatterns.put(Pattern.compile("^#\\s+import\\s+\"[a-zA-Z0-9/.]+\""), "Objective C");
		languagePatterns.put(Pattern.compile("^\\[+[a-zA-Z0-9 :]\\]"), "Objective C");
		languagePatterns.put(Pattern.compile("@interface\\s*[a-zA-Z0-9]+\\s*:\\s*[a-zA-Z0-9]+\\s*\\{"), "Objective C");		
		languagePatterns.put(Pattern.compile("\\+\\s*\\(\\s*[a-z]+\\s*\\)"), "Objective C");
		languagePatterns.put(Pattern.compile("\\-\\s*\\(\\s*[a-z]+\\s*\\)"), "Objective C");
		languagePatterns.put(Pattern.compile("@implementation\\s+[a-z]"), "Objective C");
		languagePatterns.put(Pattern.compile("@interface\\s+[a-zA-Z0-9]+\\s*:\\s*[a-zA-Z0-9]+\\s*<[a-zA-Z0-9]+>"), "Objective C");
		languagePatterns.put(Pattern.compile("@protocol\\s+[a-zA-Z0-9]+"), "Objective C");
		//languagePatterns.put(Pattern.compile("@public"), "Objective C");	//prone to false positives
		//languagePatterns.put(Pattern.compile("@private"), "Objective C"); //prone to false positives
		//languagePatterns.put(Pattern.compile("@property"), "Objective C");  //prone to false positives
		languagePatterns.put(Pattern.compile("@end\\s*$"), "Objective C");  //anchor to $ to reduce false positives in C++ code comments.
		languagePatterns.put(Pattern.compile("@synthesize"), "Objective C");
		
		//C
		//do not anchor the start pf the # lines with ^. This causes the match to fail. Why??
		languagePatterns.put(Pattern.compile("#include\\s+<[a-zA-Z0-9/]+\\.h>"), "C");
		languagePatterns.put(Pattern.compile("#include\\s+\"[a-zA-Z0-9/]+\\.h\""), "C");		
		languagePatterns.put(Pattern.compile("#define\\s+.+?$"), "C");
		languagePatterns.put(Pattern.compile("#ifndef\\s+.+?$"), "C");
		languagePatterns.put(Pattern.compile("#endif\\s*$"), "C");
		languagePatterns.put(Pattern.compile("\\s*char\\s*\\*\\*\\s*[a-zA-Z0-9_]+\\s*;"), "C");
		
		//C++
		languagePatterns.put(Pattern.compile("#include\\s+<iostream\\.h>"), "C++");
		languagePatterns.put(Pattern.compile("^[a-z0-9]+::[a-z0-9]+\\s*\\(\\s*\\).*?\\{.+?\\}", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE), "C++");  //constructor
		languagePatterns.put(Pattern.compile("(std::)?cout\\s*<<\\s*\".+?\"\\s*;"), "C++");				

		//Shell Script
		languagePatterns.put(Pattern.compile("^#!/bin/[a-z]*sh"), "Shell Script");
		
		//Python
		languagePatterns.put(Pattern.compile("#!/usr/bin/python.*$"), "Python");
		languagePatterns.put(Pattern.compile("#!/usr/bin/env\\s+python"), "Python");
		languagePatterns.put(Pattern.compile("^\\s*def\\s+[a-z0-9]+\\s*\\(\\s*[a-z0-9]+\\s*\\)\\s*:", Pattern.CASE_INSENSITIVE), "Python");
		languagePatterns.put(Pattern.compile("\\s*for\\s+[a-z0-9]+\\s+in\\s+[a-z0-9]+:", Pattern.CASE_INSENSITIVE), "Python");
		languagePatterns.put(Pattern.compile("^\\s*try\\s*:", Pattern.CASE_INSENSITIVE), "Python");
		languagePatterns.put(Pattern.compile("^\\s*except\\s*:", Pattern.CASE_INSENSITIVE), "Python");
		languagePatterns.put(Pattern.compile("^\\s*def\\s+main\\s*\\(\\s*\\)\\s*:", Pattern.CASE_INSENSITIVE), "Python");

		//Ruby		
		languagePatterns.put(Pattern.compile("^\\s*require\\s+\".+?\"\\s*$", Pattern.CASE_INSENSITIVE), "Ruby");
		languagePatterns.put(Pattern.compile("^\\s*describe\\s+[a-z0-9:]+\\s+do", Pattern.CASE_INSENSITIVE), "Ruby");
		languagePatterns.put(Pattern.compile("^\\s*class\\s+[a-z0-9]+\\s+<\\s*[a-z0-9:]+", Pattern.CASE_INSENSITIVE), "Ruby");
		languagePatterns.put(Pattern.compile("^\\s*def\\s+[a-z0-9]+\\s*.+?^\\s*end\\s*$", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE), "Ruby");
		languagePatterns.put(Pattern.compile("@@active\\s*=\\s*", Pattern.CASE_INSENSITIVE), "Ruby");
		
		//Cold Fusion
		languagePatterns.put(Pattern.compile("<cfoutput"), "Cold Fusion");		
		languagePatterns.put(Pattern.compile("<cfset"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfexecute"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfexit"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfcomponent"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cffunction"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfreturn"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfargument"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfscript"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfloop"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfquery"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfqueryparam"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfdump"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfloop"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfif"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfelseif"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("<cfelse"), "Cold Fusion");
		languagePatterns.put(Pattern.compile("writeOutput\\s*\\("), "Cold Fusion");
		languagePatterns.put(Pattern.compile("component\\s*\\{"), "Cold Fusion");		
		
		//Visual FoxPro / ActiveVFP
		languagePatterns.put(Pattern.compile("oRequest\\.querystring\\s*\\(\\s*\"[a-z0-9]+\"\\s*\\)", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE),"ActiveVFP");
		languagePatterns.put(Pattern.compile("define\\s+class\\s+[a-z0-9]+\\s+as\\s+[a-z0-9]+", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE),"ActiveVFP");
		languagePatterns.put(Pattern.compile("for\\s+[a-z0-9]+\\s*=\\s*[0-9]+\\s+to\\s+[0-9]+.+?\\s+endfor", Pattern.CASE_INSENSITIVE),"ActiveVFP");
		languagePatterns.put(Pattern.compile("do\\s+while\\s+.+?\\s+enddo", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE),"ActiveVFP");
		languagePatterns.put(Pattern.compile("if\\s+.+?\\s+endif", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE),"ActiveVFP");
		languagePatterns.put(Pattern.compile("do\\s+case\\s+case\\s+.+?\\s+endcase", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE),"ActiveVFP");
		languagePatterns.put(Pattern.compile("for\\s+each\\s+.+?\\s+endfor", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE),"ActiveVFP");
		//languagePatterns.put(Pattern.compile("oRequest"),"ActiveVFP");  //prone to false positives  
		//languagePatterns.put(Pattern.compile("oResponse"),"ActiveVFP"); //prone to false positives
		//languagePatterns.put(Pattern.compile("oSession"),"ActiveVFP");  //prone to false positives
		
		//Pascal
		languagePatterns.put(Pattern.compile("^program\\s+[a-z0-9]+;.*?begin.+?end", Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE), "Pascal");
		
		//Latex (yes, this is a programming language)
		languagePatterns.put(Pattern.compile("\\documentclass\\s*\\{[a-z]+\\}", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Latex");
		languagePatterns.put(Pattern.compile("\\begin\\s*\\{[a-z]+\\}", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Latex");
		languagePatterns.put(Pattern.compile("\\end\\s*\\{[a-z]+\\}", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE), "Latex");		
		
		//TODO: consider sorting the patterns by decreasing pattern length, so more specific patterns are tried before more general patterns
	}

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanalpha.sourcecodedisclosure.";

	/**
	 * construct the class, and register for i18n
	 */
	public SourceCodeDisclosureScanner() {
		super();
		PscanUtils.registerI18N();
	}

	/**
	 * gets the name of the scanner
	 * @return
	 */
	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	/**
	 * scans the HTTP request sent (in fact, does nothing)
	 * @param msg
	 * @param id
	 */
	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// do nothing
	}

	/**
	 * scans the HTTP response for Source Code signatures
	 * @param msg
	 * @param id
	 * @param source unused
	 */
	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		//get the body contents as a String, so we can match against it
		String responsebody = new String (msg.getResponseBody().getBytes());
		
		//try each of the patterns in turn against the response.
		//we deliberately do not assume that only status 200 responses will contain source code.
		String evidence = null;
		String programminglanguage = null;
		Iterator<Pattern> patternIterator = languagePatterns.keySet().iterator();
		while (patternIterator.hasNext()) {
			Pattern languagePattern = patternIterator.next();
			programminglanguage = languagePatterns.get(languagePattern);
			Matcher matcher = languagePattern.matcher(responsebody);
	        if (matcher.find()) {
	            evidence = matcher.group();
	            break;	//use the first match
	        }	    
		}
		if (evidence!=null && evidence.length() > 0) {
			//we found something
			Alert alert = new Alert(getId(), Alert.RISK_HIGH, Alert.WARNING, getName() + " - "+ programminglanguage );		
			     
			alert.setDetail(
					getDescription() + " - "+ programminglanguage, 
					msg.getRequestHeader().getURI().toString(), 
					"", //param
					"", //attack 
					getExtraInfo(msg, evidence),  //other info
					getSolution(), 
					getReference(), 
					evidence,	
					540,	//Information Exposure Through Source Code
					34,		//Predictable Resource Location (TODO: is this really the case here?)
					msg);  
			parent.raiseAlert(id, alert);
		}
		
	}

	/**
	 * sets the parent
	 * @param parent
	 */
	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	/**
	 * get the id of the scanner
	 * @return
	 */
	private int getId() {
		return 10099;
	}

	/**
	 * get the description of the alert
	 * @return
	 */
	private String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	/**
	 * get the solution for the alert
	 * @return
	 */
	private String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	/**
	 * gets references for the alert
	 * @return
	 */
	private String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	/**
	 * gets extra information associated with the alert
	 * @param msg
	 * @param arg0
	 * @return
	 */
	private String getExtraInfo(HttpMessage msg, String arg0) {		
		return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", arg0);        
	}

}

