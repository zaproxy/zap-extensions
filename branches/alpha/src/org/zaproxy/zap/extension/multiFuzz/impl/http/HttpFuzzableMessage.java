package org.zaproxy.zap.extension.multiFuzz.impl.http;


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
 */

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;

import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.multiFuzz.FuzzLocation;
import org.zaproxy.zap.extension.multiFuzz.MFuzzableMessage;

public class HttpFuzzableMessage extends MFuzzableMessage {

	private HttpMessage httpMessage;

	public HttpFuzzableMessage(MFuzzableMessage m) {
		this.httpMessage = (HttpMessage) m.getMessage();
	}
	public HttpFuzzableMessage(HttpMessage httpMessage) {
		this.httpMessage = httpMessage.cloneRequest();
	}
	public HttpMessage getMessage() {
		return httpMessage;
	}

	public HttpMessage fuzz(HashMap<FuzzLocation, String> subs) throws HttpMalformedHeaderException{
		ArrayList<HttpFuzzLocation> intervals = new ArrayList<HttpFuzzLocation>();
		for(FuzzLocation fl : subs.keySet()){
			intervals.add((HttpFuzzLocation) fl);
		}
		Collections.sort(intervals);
		HttpMessage fuzzedHttpMessage = httpMessage.cloneRequest();

		String origHead = fuzzedHttpMessage.getRequestHeader().toString();
		String origBody = fuzzedHttpMessage.getRequestBody().toString();
		StringBuilder head = new StringBuilder();
		StringBuilder body = new StringBuilder();
		int currPosHead = 0;
		int currPosBody = 0;
		String note = "";
		for(HttpFuzzLocation fuzzLoc : intervals)
		{
			if(fuzzLoc.header){
				if(fuzzLoc.start >= currPosHead){
					int hl = 0;
					int pos = 0;
					while (((pos = origHead.indexOf("\r\n", pos)) != -1) && (pos <= fuzzLoc.start + hl)) {
						pos += 2;
						++hl;
					}
					head.append(origHead.substring(currPosHead, fuzzLoc.start + hl));
					head.append(subs.get(fuzzLoc));
					currPosHead = fuzzLoc.end + hl;
				}
			}
			else{
				if(fuzzLoc.start >= currPosBody){
					int start = fuzzLoc.start;
					int end = fuzzLoc.end;
					if(start > origBody.length()){
						int hl = 0;
						int pos = 0;
						while (((pos = origHead.indexOf("\r\n", pos)) != -1) && (pos <= fuzzLoc.start + hl)) {
							pos += 2;
							++hl;
						}
						start -= origHead.length() - hl;
						end -= origHead.length() - hl;
						}
					body.append(origBody.substring(currPosBody, start));
					body.append(subs.get(fuzzLoc));
					currPosBody = end;
				}
			}
			note += subs.get(fuzzLoc);
		}
		head.append(origHead.substring(currPosHead));
		body.append(origBody.substring(currPosBody));

		fuzzedHttpMessage.setRequestHeader(head.toString());
		fuzzedHttpMessage.setRequestBody(body.toString());
		fuzzedHttpMessage.setNote(note);
		return fuzzedHttpMessage;
	}
	@Override
	public Message fuzz(String fuzzString) throws Exception {
		return null;
	}
	@Override
	public String representName(FuzzLocation l) {
		HttpFuzzLocation loc = (HttpFuzzLocation) l;
		if(loc.header){
			return httpMessage.getRequestHeader().toString().substring(loc.start, loc.end);
		}
		if(!loc.header){
			String header = httpMessage.getRequestHeader().toString();
			int headerLen = header.length();
			int hl = 0;
			int pos = 0;
			while ((pos = header.indexOf("\r\n", pos)) != -1) {
				pos += 2;
				++hl;
			}
			int bl = httpMessage.getRequestBody().toString().length();
			if(loc.start < bl){
				return httpMessage.getRequestBody().toString().substring(loc.start, loc.end);
			}
			else{
				return httpMessage.getRequestBody().toString().substring(loc.start + hl - headerLen, loc.end + hl - headerLen);
			}
		}
		return null;
	}
}