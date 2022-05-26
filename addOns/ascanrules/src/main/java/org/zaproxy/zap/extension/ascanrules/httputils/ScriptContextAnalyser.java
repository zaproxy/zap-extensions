/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules.httputils;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import net.htmlparser.jericho.Attribute;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.network.HttpMessage;


// parser 
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;


public class ScriptContextAnalyser {

    private HttpMessage msg = null;
    private String htmlPage = null;

	private static final String PARSE_URL = "https://paserjs.herokuapp.com/parse";
	private static final String CONTEXT_URL = "https://paserjs.herokuapp.com/context";



    private String scriptBlockCode = null;

    public ScriptContextAnalyser(HttpMessage msg){
        this.msg = msg;
        this.htmlPage = msg.getResponseBody().toString();
        System.err.println("msg:" + this.msg);
        System.err.println("html:" + this.htmlPage);

    }

    public ScriptContext getScriptContexts(String target){
        // get script block

        // find context
        ScriptContext scriptContext = new ScriptContext(this.msg, target);
        String contextQuote;

        System.err.println("getting script contexts");

        String params = "code=" + this.htmlPage + "&target=" + target;

        try {
            contextQuote = sendPOST(CONTEXT_URL, params); 
        } catch (Exception e) {
            return scriptContext;
        }

        if (contextQuote.equals("\"")){
            scriptContext.setSurroundingQuote("\"");
        }
        else if (contextQuote.equals("'")){
            scriptContext.setSurroundingQuote("'");
        }
        else if (contextQuote.equals("")){
            scriptContext.setSurroundingQuote("");
        }
        
        return scriptContext;

    }


    private static String sendPOST(String url, String params) throws IOException {
		URL obj = new URL(url);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();
		con.setRequestMethod("POST");

		// For POST only - START
		con.setDoOutput(true);
		OutputStream os = con.getOutputStream();
		os.write(params.getBytes());
		os.flush();
		os.close();
		// For POST only - END

		int responseCode = con.getResponseCode();
		System.out.println("POST Response Code :: " + responseCode);

		if (responseCode == HttpURLConnection.HTTP_OK) { //success
			BufferedReader in = new BufferedReader(new InputStreamReader(
					con.getInputStream()));
			String inputLine;
			StringBuffer response = new StringBuffer();

			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			in.close();

			return response.toString();

		
		} else {
			return null;
		}
	}
    
}
