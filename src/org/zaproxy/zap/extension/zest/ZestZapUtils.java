/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import java.text.DecimalFormat;
import java.text.MessageFormat;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestActionFail;
import org.mozilla.zest.core.v1.ZestActionScan;
import org.mozilla.zest.core.v1.ZestActionSetToken;
import org.mozilla.zest.core.v1.ZestAssertBodyRegex;
import org.mozilla.zest.core.v1.ZestAssertHeaderRegex;
import org.mozilla.zest.core.v1.ZestAssertLength;
import org.mozilla.zest.core.v1.ZestAssertStatusCode;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestConditionRegex;
import org.mozilla.zest.core.v1.ZestConditionResponseTime;
import org.mozilla.zest.core.v1.ZestConditionStatusCode;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestTransformFieldReplace;
import org.mozilla.zest.core.v1.ZestTransformRndIntReplace;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;

public class ZestZapUtils {

    private static final Logger log = Logger.getLogger(ZestZapUtils.class);
	
	public static String toUiString(ZestElement za) {
		return toUiString(za, true, false);
	}

	public static String toUiString(ZestElement za, boolean incParams) {
		return toUiString(za, incParams, false);
	}

	public static String toUiString(ZestElement za, boolean incParams, boolean isShadow) {
		if (za instanceof ZestScript) {
			ZestScript zs = (ZestScript) za;
			return MessageFormat.format(
					Constant.messages.getString("zest.element.script"), zs.getTitle());
		} else if (za instanceof ZestRequest) {
			ZestRequest zr = (ZestRequest) za;
			return MessageFormat.format(
					Constant.messages.getString("zest.element.request"), zr.getMethod(), zr.getUrl());
			
		} else if (za instanceof ZestResponse) {
			ZestResponse zr = (ZestResponse) za;
			return MessageFormat.format(
					Constant.messages.getString("zest.element.response"), zr.getStatusCode());
			
		} else if (za instanceof ZestAssertStatusCode) {
			ZestAssertStatusCode sca = (ZestAssertStatusCode) za;
			if (incParams) {
				return MessageFormat.format(
						Constant.messages.getString("zest.element.assert.statuscode"), sca.getCode());
			} else {
				return Constant.messages.getString("zest.element.assert.statuscode.title");
			}
			
		} else if (za instanceof ZestAssertLength) {
			ZestAssertLength sla = (ZestAssertLength) za;
			if (incParams) {
				return MessageFormat.format(
						Constant.messages.getString("zest.element.assert.length"), sla.getLength(), sla.getApprox());
			} else {
				return Constant.messages.getString("zest.element.assert.length.title");
			}
			
		} else if (za instanceof ZestAssertHeaderRegex) {
			ZestAssertHeaderRegex zhr = (ZestAssertHeaderRegex) za;
			if (incParams) {
				if (zhr.isInverse()) {
					return MessageFormat.format(
							Constant.messages.getString("zest.element.assert.headregex.exc"), zhr.getRegex());
				} else {
					return MessageFormat.format(
							Constant.messages.getString("zest.element.assert.headregex.inc"), zhr.getRegex());
				}
			} else {
				return Constant.messages.getString("zest.element.assert.headregex.title");
			}
			
		} else if (za instanceof ZestAssertBodyRegex) {
			ZestAssertBodyRegex zbr = (ZestAssertBodyRegex) za;
			if (incParams) {
				if (zbr.isInverse()) {
					return MessageFormat.format(
							Constant.messages.getString("zest.element.assert.bodyregex.exc"), zbr.getRegex());
				} else {
					return MessageFormat.format(
							Constant.messages.getString("zest.element.assert.bodyregex.inc"), zbr.getRegex());
				}
			} else {
				return Constant.messages.getString("zest.element.assert.bodyregex.title");
			}
		} else if (za instanceof ZestConditionRegex) {
			ZestConditionRegex zhr = (ZestConditionRegex) za;
			if (incParams) {
				if (isShadow) {
					return MessageFormat.format(
							Constant.messages.getString("zest.element.condition.else.regex"), zhr.getLocation(), zhr.getRegex());
				} else {
					return MessageFormat.format(
							Constant.messages.getString("zest.element.condition.if.regex"), zhr.getLocation(), zhr.getRegex());
				}
			} else {
				return Constant.messages.getString("zest.element.condition.regex.title");
			}
			
		} else if (za instanceof ZestConditionStatusCode) {
			ZestConditionStatusCode zhr = (ZestConditionStatusCode) za;
			if (incParams) {
				if (isShadow) {
					return MessageFormat.format(
							Constant.messages.getString("zest.element.condition.else.status"), zhr.getCode());
				} else {
					return MessageFormat.format(
							Constant.messages.getString("zest.element.condition.if.status"), zhr.getCode());
				}
			} else {
				return Constant.messages.getString("zest.element.condition.status.title");
			}
			
		} else if (za instanceof ZestConditionResponseTime) {
			ZestConditionResponseTime zhr = (ZestConditionResponseTime) za;
			if (incParams) {
				if (zhr.isGreaterThan()) {
					if (isShadow) {
						return MessageFormat.format(
								Constant.messages.getString("zest.element.condition.else.resptimegt"), zhr.getTimeInMs());
					} else {
						return MessageFormat.format(
								Constant.messages.getString("zest.element.condition.if.resptimegt"), zhr.getTimeInMs());
					}
				} else {
					if (isShadow) {
						return MessageFormat.format(
								Constant.messages.getString("zest.element.condition.else.resptimelt"), zhr.getTimeInMs());
					} else {
						return MessageFormat.format(
								Constant.messages.getString("zest.element.condition.if.resptimelt"), zhr.getTimeInMs());
					}
				}
			} else {
				return Constant.messages.getString("zest.element.condition.status.resptime");
			}
			
		} else if (za instanceof ZestTransformFieldReplace) {
			ZestTransformFieldReplace zt = (ZestTransformFieldReplace) za;
			if (incParams) {
				return MessageFormat.format(
						Constant.messages.getString("zest.element.transform.fieldrep"), 
						zt.getRequestString(), zt.getFieldDefinition().getKey());
			} else {
				return Constant.messages.getString("zest.element.transform.fieldrep.title");
			}
			
		} else if (za instanceof ZestTransformRndIntReplace) {
			ZestTransformRndIntReplace zt = (ZestTransformRndIntReplace) za;
			if (incParams) {
				return MessageFormat.format(
						Constant.messages.getString("zest.element.transform.rndint"), 
						zt.getRequestString(), zt.getMinInt(), zt.getMaxInt());
			} else {
				return Constant.messages.getString("zest.element.transform.rndint.title");
			}
			
		} else if (za instanceof ZestActionScan) {
			ZestActionScan zsa = (ZestActionScan) za;
			if (incParams) {
				return MessageFormat.format(
						Constant.messages.getString("zest.element.action.scan"), zsa.getTargetParameter());
			} else {
				return Constant.messages.getString("zest.element.action.scan.title");
			}
			
		} else if (za instanceof ZestActionSetToken) {
			ZestActionSetToken zsa = (ZestActionSetToken) za;
			if (incParams) {
				return MessageFormat.format(
						Constant.messages.getString("zest.element.action.settoken"), 
						zsa.getTokenName(), zsa.getPrefix(), zsa.getPostfix());
			} else {
				return Constant.messages.getString("zest.element.action.settoken.title");
			}
			
		} else if (za instanceof ZestActionFail) {
			ZestActionFail zsa = (ZestActionFail) za;
			if (incParams) {
				return MessageFormat.format(
						Constant.messages.getString("zest.element.action.fail"), zsa.getMessage());
			} else {
				return Constant.messages.getString("zest.element.action.fail.title");
			}
			
		} else {
			return MessageFormat.format(
					Constant.messages.getString("zest.element.unknown"), za.getClass().getCanonicalName());
		}
	}
	
	public static String toUiFailureString(ZestAssertion za, ZestResponse response) {
		if (za instanceof ZestAssertLength) {
			ZestAssertLength sla = (ZestAssertLength) za;
			int intDiff = 100;
			if (response.getBody() != null) {
				if (sla.getLength() == 0) {
					if (sla.getLength() == 0) {
						intDiff = 0;
					}
				} else {
					intDiff = (sla.getLength() - response.getBody().length()) * 100 / sla.getLength();
				}
			}
			String strDiff = Integer.toString(intDiff);
			if (intDiff == 1) {
				// Show to one decimal place
				DecimalFormat df = new DecimalFormat("#.#");
				strDiff = df.format(((double)(sla.getLength() - response.getBody().length()) * 100) / sla.getLength());
			} else if (intDiff == 0) {
				// Show to two decimal place
				DecimalFormat df = new DecimalFormat("#.##");
				strDiff = df.format(((double)(sla.getLength() - response.getBody().length()) * 100) / sla.getLength());
			}			
			return MessageFormat.format(
					Constant.messages.getString("zest.fail.assert.length"), 
					sla.getLength(), response.getBody().length(), strDiff); 
		} else if (za instanceof ZestAssertStatusCode) {
			ZestAssertStatusCode sca = (ZestAssertStatusCode) za;
			return MessageFormat.format(
					Constant.messages.getString("zest.fail.assert.statuscode"), sca.getCode(), response.getStatusCode());
		} else if (za instanceof ZestAssertHeaderRegex) {
			ZestAssertHeaderRegex zhr = (ZestAssertHeaderRegex) za;
			if (zhr.isInverse()) {
				return MessageFormat.format(
						Constant.messages.getString("zest.fail.assert.headregex.exc"), zhr.getRegex());
			} else {
				return MessageFormat.format(
						Constant.messages.getString("zest.fail.assert.headregex.inc"), zhr.getRegex());
			}
		} else if (za instanceof ZestAssertBodyRegex) {
			ZestAssertBodyRegex zbr = (ZestAssertBodyRegex) za;
			if (zbr.isInverse()) {
				return MessageFormat.format(
						Constant.messages.getString("zest.fail.assert.bodyregex.exc"), zbr.getRegex());
			} else {
				return MessageFormat.format(
						Constant.messages.getString("zest.fail.assert.bodyregex.inc"), zbr.getRegex());
			}
		}
		return toUiString(za, true); 
	}

	public static HttpMessage toHttpMessage(ZestRequest request, ZestResponse response) 
			throws URIException, HttpMalformedHeaderException {
		HttpMessage msg = new HttpMessage(new URI(request.getUrl().toString(), false));
		if (request.getHeaders() != null) {
			try {
				msg.setRequestHeader(msg.getRequestHeader().getPrimeHeader() + "\r\n" + request.getHeaders());
			} catch (HttpMalformedHeaderException e) {
				log.error(e.getMessage(), e);
			}
		}
		msg.getRequestHeader().setMethod(request.getMethod());
		msg.setRequestBody(request.getData());
		
		try {
			msg.setResponseHeader(new HttpResponseHeader(response.getHeaders()));
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}
		msg.setResponseBody(response.getBody());
		msg.setTimeElapsedMillis((int)response.getResponseTimeInMs());
		
		return msg;
	}

}
