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

import java.net.MalformedURLException;
import java.net.URL;
import java.sql.SQLException;
import java.text.MessageFormat;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestActionFail;
import org.mozilla.zest.core.v1.ZestActionScan;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestAssignFieldValue;
import org.mozilla.zest.core.v1.ZestAssignRandomInteger;
import org.mozilla.zest.core.v1.ZestAssignRegexDelimiters;
import org.mozilla.zest.core.v1.ZestAssignStringDelimiters;
import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestExpressionLength;
import org.mozilla.zest.core.v1.ZestExpressionRegex;
import org.mozilla.zest.core.v1.ZestExpressionResponseTime;
import org.mozilla.zest.core.v1.ZestExpressionStatusCode;
import org.mozilla.zest.core.v1.ZestExpressionURL;
import org.mozilla.zest.core.v1.ZestLoopFile;
import org.mozilla.zest.core.v1.ZestLoopInteger;
import org.mozilla.zest.core.v1.ZestLoopString;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestScript;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.script.ScriptNode;

public class ZestZapUtils {

	private static final Logger log = Logger.getLogger(ZestZapUtils.class);

	public static String toUiString(ZestElement za) {
		return toUiString(za, true, false);
	}

	public static String toUiString(ZestElement za, boolean incParams) {
		return toUiString(za, incParams, false);
	}

	public static String toUiString(ZestElement za, boolean incParams,
			boolean isShadow) {
		if (za instanceof ZestScript) {
			ZestScript zs = (ZestScript) za;
			return MessageFormat.format(
					Constant.messages.getString("zest.element.script"),
					zs.getTitle());
		} else if (za instanceof ZestRequest) {
			ZestRequest zr = (ZestRequest) za;
			if (zr.getUrl() != null) {
				return MessageFormat.format(
						Constant.messages.getString("zest.element.request"),
						zr.getMethod(), zr.getUrl());
			} else {
				return MessageFormat.format(
						Constant.messages.getString("zest.element.request"),
						zr.getMethod(), zr.getUrlToken());
			}
		} else if (za instanceof ZestResponse) {
			ZestResponse zr = (ZestResponse) za;
			return MessageFormat.format(
					Constant.messages.getString("zest.element.response"),
					zr.getStatusCode());

		} else if (za instanceof ZestAssertion) {
			ZestAssertion zas = (ZestAssertion) za;
			return MessageFormat.format(
					Constant.messages.getString("zest.element.assert"),
					toUiString((ZestElement) zas.getRootExpression(),
							incParams, isShadow));

		} else if (za instanceof ZestConditional) {
			ZestConditional zac = (ZestConditional) za;
			if (isShadow) {
				return Constant.messages
						.getString("zest.element.conditional.else");
			} else {
				return MessageFormat.format(
						Constant.messages
								.getString("zest.element.conditional.if"),
						toUiString((ZestElement) zac.getRootExpression(),
								incParams, isShadow));
			}

		} else if (za instanceof ZestExpressionStatusCode) {
			ZestExpressionStatusCode sca = (ZestExpressionStatusCode) za;
			if (incParams) {
				return MessageFormat.format(Constant.messages
						.getString("zest.element.expression.statuscode"), sca
						.getCode());
			} else {
				return Constant.messages
						.getString("zest.element.expression.statuscode.title");
			}
		} else if (za instanceof ZestExpressionLength) {
			ZestExpressionLength sla = (ZestExpressionLength) za;
			if (incParams) {
				return MessageFormat.format(Constant.messages
						.getString("zest.element.expression.length"), sla
						.getLength(), sla.getApprox());
			} else {
				return Constant.messages
						.getString("zest.element.expression.length.title");
			}
		} else if (za instanceof ZestExpressionResponseTime) {
			ZestExpressionResponseTime zhr = (ZestExpressionResponseTime) za;
			if (incParams) {
				if (zhr.isGreaterThan()) {
					return MessageFormat.format(Constant.messages
							.getString("zest.element.expression.resptimegt"),
							zhr.getTimeInMs());
				} else {
					return MessageFormat.format(Constant.messages
							.getString("zest.element.expression.resptimelt"),
							zhr.getTimeInMs());
				}
			} else {
				return Constant.messages
						.getString("zest.element.expression.resptime.title");
			}
		} else if (za instanceof ZestExpressionRegex) {
			ZestExpressionRegex zer = (ZestExpressionRegex) za;
			if (incParams) {
				if (zer.isInverse()) {
					return MessageFormat.format(Constant.messages
							.getString("zest.element.expression.regex.exc"),
							zer.getLocation(), zer.getRegex());
				} else {
					return MessageFormat.format(Constant.messages
							.getString("zest.element.expression.regex.inc"),
							zer.getLocation(), zer.getRegex());
				}
			} else {
				return Constant.messages
						.getString("zest.element.expression.regex.title");
			}
		} else if (za instanceof ZestExpressionURL) {
			ZestExpressionURL zeu = (ZestExpressionURL) za;

			StringBuilder incSb = new StringBuilder();
			for (String str : zeu.getIncludeRegexes()) {
				incSb.append(str);
				incSb.append(" ");
			}
			String incStr = incSb.toString();
			if (incStr.length() > 20) {
				incStr = incStr.substring(0, 20) + "...";
			}

			StringBuilder excSb = new StringBuilder();
			for (String str : zeu.getExcludeRegexes()) {
				excSb.append(str);
				excSb.append(" ");
			}
			String excStr = excSb.toString();
			if (excStr.length() > 20) {
				excStr = excStr.substring(0, 20) + "...";
			}

			if (incParams) {
				return MessageFormat.format(Constant.messages
						.getString("zest.element.expression.url"), incStr,
						excStr);
			} else {
				return Constant.messages
						.getString("zest.element.expression.url.title");
			}

		} else if (za instanceof ZestLoopString) {
			ZestLoopString zals = (ZestLoopString) za;
			return MessageFormat.format(Constant.messages.getString("zest.element.loop.string.title"),
					(Object[]) zals.getValues());
		} else if (za instanceof ZestLoopFile) {
			ZestLoopFile zalf = (ZestLoopFile) za;
			return MessageFormat.format(Constant.messages.getString("zest.element.loop.file.title"), zalf
					.getFile().getAbsolutePath());
		} else if (za instanceof ZestLoopInteger) {
			ZestLoopInteger zali = (ZestLoopInteger) za;
			return MessageFormat.format(Constant.messages.getString("zest.element.loop.integer.title"),
					" FROM ", zali.getStart(), " TO ", zali.getEnd());
		 } else if (za instanceof ZestAssignFieldValue) {
             ZestAssignFieldValue zsa = (ZestAssignFieldValue) za;
             if (incParams) {
                     return MessageFormat.format(
                                     Constant.messages.getString("zest.element.assign.field"), 
                                     zsa.getVariableName(), zsa.getFieldDefinition().getFormIndex(), zsa.getFieldDefinition().getFieldName());
             } else {
                     return Constant.messages.getString("zest.element.assign.field.title");
             }
             
     } else if (za instanceof ZestAssignRegexDelimiters) {
             ZestAssignRegexDelimiters zsa = (ZestAssignRegexDelimiters) za;
             if (incParams) {
                     return MessageFormat.format(
                                     Constant.messages.getString("zest.element.assign.regex"), 
                                     zsa.getVariableName(), zsa.getPrefix(), zsa.getPostfix());
             } else {
                     return Constant.messages.getString("zest.element.assign.regex.title");
             }
             
     } else if (za instanceof ZestAssignStringDelimiters) {
             ZestAssignStringDelimiters zsa = (ZestAssignStringDelimiters) za;
             if (incParams) {
                     return MessageFormat.format(
                                     Constant.messages.getString("zest.element.assign.string"), 
                                     zsa.getVariableName(), zsa.getPrefix(), zsa.getPostfix());
             } else {
                     return Constant.messages.getString("zest.element.assign.string.title");
             }
             
     } else if (za instanceof ZestAssignRandomInteger) {
             ZestAssignRandomInteger zsa = (ZestAssignRandomInteger) za;
             if (incParams) {
                     return MessageFormat.format(
                                     Constant.messages.getString("zest.element.assign.rndint"), 
                                     zsa.getVariableName(), zsa.getMinInt(), zsa.getMaxInt());
             } else {
                     return Constant.messages.getString("zest.element.assign.rndint.title");
             }

     } else if (za instanceof ZestActionScan) {
			ZestActionScan zsa = (ZestActionScan) za;
			if (incParams) {
				return MessageFormat
						.format(Constant.messages
								.getString("zest.element.action.scan"), zsa
								.getTargetParameter());
			} else {
				return Constant.messages
						.getString("zest.element.action.scan.title");
			}

		} else if (za instanceof ZestActionFail) {
			ZestActionFail zsa = (ZestActionFail) za;
			if (incParams) {
				return MessageFormat
						.format(Constant.messages
								.getString("zest.element.action.fail"), zsa
								.getMessage());
			} else {
				return Constant.messages
						.getString("zest.element.action.fail.title");
			}
			/*
			 * } else if (za instanceof ZestTreeElement) { switch
			 * (((ZestTreeElement)za).getType()) { case TARGETED_SCRIPT: return
			 * Constant.messages.getString("zest.element.targetedscript"); case
			 * ACTIVE_SCRIPT: return
			 * Constant.messages.getString("zest.element.activescript"); case
			 * PASSIVE_SCRIPT: return
			 * Constant.messages.getString("zest.element.passivescript"); case
			 * COMMON_TESTS: return
			 * Constant.messages.getString("zest.element.commontests"); }
			 */
		}

		return MessageFormat.format(Constant.messages
				.getString("zest.element.unknown"), za.getClass()
				.getCanonicalName());
	}

	public static String toUiFailureString(ZestAssertion za,
			ZestResponse response) {
		/*
		 * if (za instanceof ZestAssertLength) { ZestAssertLength sla =
		 * (ZestAssertLength) za; int intDiff = 100; if (response.getBody() !=
		 * null) { if (sla.getLength() == 0) { if (sla.getLength() == 0) {
		 * intDiff = 0; } } else { intDiff = (sla.getLength() -
		 * response.getBody().length()) * 100 / sla.getLength(); } } String
		 * strDiff = Integer.toString(intDiff); if (intDiff == 1) { // Show to
		 * one decimal place DecimalFormat df = new DecimalFormat("#.#");
		 * strDiff = df.format(((double)(sla.getLength() -
		 * response.getBody().length()) * 100) / sla.getLength()); } else if
		 * (intDiff == 0) { // Show to two decimal place DecimalFormat df = new
		 * DecimalFormat("#.##"); strDiff = df.format(((double)(sla.getLength()
		 * - response.getBody().length()) * 100) / sla.getLength()); } return
		 * MessageFormat.format(
		 * Constant.messages.getString("zest.fail.assert.length"),
		 * sla.getLength(), response.getBody().length(), strDiff); } else if (za
		 * instanceof ZestAssertStatusCode) { ZestAssertStatusCode sca =
		 * (ZestAssertStatusCode) za; return MessageFormat.format(
		 * Constant.messages.getString("zest.fail.assert.statuscode"),
		 * sca.getCode(), response.getStatusCode()); } else if (za instanceof
		 * ZestAssertHeaderRegex) { ZestAssertHeaderRegex zhr =
		 * (ZestAssertHeaderRegex) za; if (zhr.isInverse()) { return
		 * MessageFormat.format(
		 * Constant.messages.getString("zest.fail.assert.headregex.exc"),
		 * zhr.getRegex()); } else { return MessageFormat.format(
		 * Constant.messages.getString("zest.fail.assert.headregex.inc"),
		 * zhr.getRegex()); } } else if (za instanceof ZestAssertBodyRegex) {
		 * ZestAssertBodyRegex zbr = (ZestAssertBodyRegex) za; if
		 * (zbr.isInverse()) { return MessageFormat.format(
		 * Constant.messages.getString("zest.fail.assert.bodyregex.exc"),
		 * zbr.getRegex()); } else { return MessageFormat.format(
		 * Constant.messages.getString("zest.fail.assert.bodyregex.inc"),
		 * zbr.getRegex()); } }
		 */
		return toUiString(za, true);
	}

	public static HttpMessage toHttpMessage(ZestRequest request,
			ZestResponse response) throws URIException,
			HttpMalformedHeaderException {
		HttpMessage msg;
		if (request.getUrl() != null) {
			msg = new HttpMessage(new URI(request.getUrl().toString(), false));
		} else {
			// TODO - there a better option?
			return null;
		}
		if (request.getHeaders() != null) {
			try {
				msg.setRequestHeader(msg.getRequestHeader().getPrimeHeader()
						+ "\r\n" + request.getHeaders());
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
		msg.setTimeElapsedMillis((int) response.getResponseTimeInMs());

		return msg;
	}

	public static ZestResponse toZestResponse(HttpMessage msg)
			throws MalformedURLException {
		return new ZestResponse(new URL(msg.getRequestHeader().getURI()
				.toString()), msg.getResponseHeader().toString(), msg
				.getResponseBody().toString(), msg.getResponseHeader()
				.getStatusCode(), msg.getTimeElapsedMillis());
	}

	public static ZestRequest toZestRequest(HttpMessage msg)
			throws MalformedURLException, HttpMalformedHeaderException,
			SQLException {
		ZestRequest req = new ZestRequest();
		req.setMethod(msg.getRequestHeader().getMethod());
		if (msg.getRequestHeader().getURI() != null) {
			req.setUrl(new URL(msg.getRequestHeader().getURI().toString()));
		}
		req.setUrlToken(correctTokens(msg.getRequestHeader().getURI()
				.toString()));
		req.setHeaders(correctTokens(msg.getRequestHeader()
				.getHeadersAsString()));
		req.setData(correctTokens(msg.getRequestBody().toString()));
		return req;
	}

	private static String correctTokens(String str) {
		return str.replace("%7B%7B", "{{").replace("%7D%7D", "}}");
	}

	public static boolean isZestNode(ScriptNode node) {
		if (node == null || node.getUserObject() == null) {
			return false;
		}
		return node.getUserObject() instanceof ZestScriptWrapper
				|| node.getUserObject() instanceof ZestElementWrapper;
	}

	public static ZestElement getElement(ScriptNode node) {
		if (node == null || node.getUserObject() == null) {
			return null;
		}
		if (node.getUserObject() instanceof ZestScriptWrapper) {
			return ((ZestScriptWrapper) node.getUserObject()).getZestScript();
		}
		if (node.getUserObject() instanceof ZestElementWrapper) {
			return ((ZestElementWrapper) node.getUserObject()).getElement();
		}
		log.debug("getElement " + node.getNodeName() + " Unrecognised class: "
				+ node.getUserObject().getClass().getCanonicalName());
		return null;
	}

	public static boolean isShadow(ScriptNode node) {
		if (node == null || node.getUserObject() == null) {
			return false;
		}
		if (node.getUserObject() instanceof ZestElementWrapper) {
			return ((ZestElementWrapper) node.getUserObject()).isShadow();
		}
		return false;
	}

}
