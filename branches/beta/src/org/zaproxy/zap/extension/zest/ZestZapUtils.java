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

import java.awt.event.InputEvent;
import java.awt.event.MouseAdapter;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.SQLException;
import java.text.DecimalFormat;
import java.text.MessageFormat;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestActionFail;
import org.mozilla.zest.core.v1.ZestActionIntercept;
import org.mozilla.zest.core.v1.ZestActionInvoke;
import org.mozilla.zest.core.v1.ZestActionPrint;
import org.mozilla.zest.core.v1.ZestActionScan;
import org.mozilla.zest.core.v1.ZestActionSleep;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestAssignFieldValue;
import org.mozilla.zest.core.v1.ZestAssignRandomInteger;
import org.mozilla.zest.core.v1.ZestAssignRegexDelimiters;
import org.mozilla.zest.core.v1.ZestAssignReplace;
import org.mozilla.zest.core.v1.ZestAssignString;
import org.mozilla.zest.core.v1.ZestAssignStringDelimiters;
import org.mozilla.zest.core.v1.ZestComment;
import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestControlLoopBreak;
import org.mozilla.zest.core.v1.ZestControlLoopNext;
import org.mozilla.zest.core.v1.ZestControlReturn;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestExpressionAnd;
import org.mozilla.zest.core.v1.ZestExpressionEquals;
import org.mozilla.zest.core.v1.ZestExpressionLength;
import org.mozilla.zest.core.v1.ZestExpressionOr;
import org.mozilla.zest.core.v1.ZestExpressionRegex;
import org.mozilla.zest.core.v1.ZestExpressionResponseTime;
import org.mozilla.zest.core.v1.ZestExpressionStatusCode;
import org.mozilla.zest.core.v1.ZestExpressionURL;
import org.mozilla.zest.core.v1.ZestLoopFile;
import org.mozilla.zest.core.v1.ZestLoopInteger;
import org.mozilla.zest.core.v1.ZestLoopString;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestRuntime;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ScriptNode;

public class ZestZapUtils {

	private static final String ZEST_VAR_VALID_CHRS = "-:.";
	
	private static final Logger log = Logger.getLogger(ZestZapUtils.class);
	
	// Only use for debugging for now, as the tree wont be fully updated if indexes change
	private static boolean showIndexes = false;

	public static String toUiString(ZestElement za) {
		return toUiString(za, true, 0);
	}

	public static String toUiString(ZestElement za, boolean incParams) {
		return toUiString(za, incParams, 0);
	}

	public static String toUiString(ZestElement za, boolean incParams,
			int shadowLevel) {
		String indexStr = "";
		if (showIndexes && za instanceof ZestStatement) {
			indexStr = ((ZestStatement)za).getIndex() + ": ";
		}
		
		if (za instanceof ZestScript) {
			ZestScript zs = (ZestScript) za;
			return indexStr + MessageFormat.format(
					Constant.messages.getString("zest.element.script"),
					zs.getTitle());
		} else if (za instanceof ZestRequest) {
			ZestRequest zr = (ZestRequest) za;
			if (zr.getUrl() != null) {
				return indexStr + MessageFormat.format(
						Constant.messages.getString("zest.element.request"),
						zr.getMethod(), zr.getUrl());
			} else {
				return indexStr + MessageFormat.format(
						Constant.messages.getString("zest.element.request"),
						zr.getMethod(), zr.getUrlToken());
			}
		} else if (za instanceof ZestResponse) {
			ZestResponse zr = (ZestResponse) za;
			return indexStr + MessageFormat.format(
					Constant.messages.getString("zest.element.response"),
					zr.getStatusCode());

		} else if (za instanceof ZestAssertion) {
			ZestAssertion zas = (ZestAssertion) za;
			return indexStr + MessageFormat.format(
					Constant.messages.getString("zest.element.assert"),
					toUiString((ZestElement) zas.getRootExpression(),
							incParams, shadowLevel));

		} else if (za instanceof ZestConditional) {
			ZestConditional zac = (ZestConditional) za;
			if (shadowLevel == 0) {
				if (zac.getRootExpression() != null) {
					return indexStr + Constant.messages
							.getString("zest.element.conditional.if")
							+ toUiString((ZestElement) zac.getRootExpression(),
									false, 0);
				} else {
					return indexStr + Constant.messages
							.getString("zest.element.conditional.if")+" ";
				}
			} else if (shadowLevel == 1) {
				return indexStr + Constant.messages
						.getString("zest.element.conditional.then");
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.conditional.else");
//				if (zac.getRootExpression() != null) {
//					return indexStr + MessageFormat
//							.format(Constant.messages
//									.getString("zest.element.conditional.else"),
//									toUiString((ZestElement) zac
//											.getRootExpression(), incParams,
//											shadowLevel));
//				} else {
//					return indexStr + MessageFormat.format(Constant.messages
//							.getString("zest.element.conditional.else"), "");
//				}
			}
		} else if (za instanceof ZestExpressionAnd) {
			return indexStr + MessageFormat
					.format(Constant.messages
							.getString("zest.element.expression.and"),
							incParams);
		} else if (za instanceof ZestExpressionOr){
			return indexStr + MessageFormat.format(Constant.messages.getString("zest.element.expression.or"), incParams);
		} else if (za instanceof ZestExpressionStatusCode) {
			ZestExpressionStatusCode sca = (ZestExpressionStatusCode) za;
			if (incParams) {
				return indexStr + MessageFormat.format(Constant.messages
						.getString("zest.element.expression.statuscode"), sca
						.getCode());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.expression.statuscode.title");
			}
		} else if (za instanceof ZestExpressionLength) {
			ZestExpressionLength sla = (ZestExpressionLength) za;
			if (incParams) {
				return indexStr + MessageFormat.format(Constant.messages
						.getString("zest.element.expression.length"), sla
						.getVariableName(), sla.getLength(), sla.getApprox());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.expression.length.title");
			}
		} else if (za instanceof ZestExpressionResponseTime) {
			ZestExpressionResponseTime zhr = (ZestExpressionResponseTime) za;
			if (incParams) {
				if (zhr.isGreaterThan()) {
					return indexStr + MessageFormat.format(Constant.messages
							.getString("zest.element.expression.resptimegt"),
							zhr.getTimeInMs());
				} else {
					return indexStr + MessageFormat.format(Constant.messages
							.getString("zest.element.expression.resptimelt"),
							zhr.getTimeInMs());
				}
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.expression.resptime.title");
			}
		} else if (za instanceof ZestExpressionRegex) {
			// TODO case exact
			// TODO what about exp inverse ??
			ZestExpressionRegex zer = (ZestExpressionRegex) za;
			if (incParams) {
				if (zer.isInverse()) {
					return indexStr + MessageFormat.format(Constant.messages
							.getString("zest.element.expression.regex.exc"),
							zer.getVariableName(), zer.getRegex());
				} else {
					return indexStr + MessageFormat.format(Constant.messages
							.getString("zest.element.expression.regex.inc"),
							zer.getVariableName(), zer.getRegex());
				}
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.expression.regex.title");
			}
		} else if (za instanceof ZestExpressionEquals) {
			// TODO case exact
			ZestExpressionEquals zer = (ZestExpressionEquals) za;
			if (incParams) {
				return indexStr + MessageFormat.format(Constant.messages
						.getString("zest.element.expression.equals"), zer
						.getVariableName(), zer.getValue());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.expression.equals.title");
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
				return indexStr + MessageFormat.format(Constant.messages
						.getString("zest.element.expression.url"), incStr,
						excStr);
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.expression.url.title");
			}

		} else if (za instanceof ZestLoopString) {
			ZestLoopString zals = (ZestLoopString) za;
			if (incParams) {
				// Build up a list of the linitial values
				StringBuilder vals = new StringBuilder();
				for (String val : zals.getValues()) {
					if (vals.length() > 0) {
						vals.append(", ");
					}
					if (vals.length() > 20) {
						vals.append("...");
						break;
					}
					vals.append(val);
				}

				return indexStr + MessageFormat
						.format(Constant.messages
								.getString("zest.element.loop.string"), zals
								.getVariableName(), vals.toString());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.loop.string.title");

			}
		} else if (za instanceof ZestLoopFile) {
			ZestLoopFile zalf = (ZestLoopFile) za;
			if (incParams) {
				return indexStr + MessageFormat.format(Constant.messages
						.getString("zest.element.loop.file"), zalf
						.getVariableName(), zalf.getFile().getName());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.loop.file.title");
			}
		} else if (za instanceof ZestLoopInteger) {
			ZestLoopInteger zali = (ZestLoopInteger) za;
			if (incParams) {
				return indexStr + MessageFormat.format(Constant.messages
						.getString("zest.element.loop.integer"), zali
						.getVariableName(), zali.getStart(), zali.getEnd(),
						zali.getStep());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.loop.integer.title");
			}
		} else if (za instanceof ZestAssignFieldValue) {
			ZestAssignFieldValue zsa = (ZestAssignFieldValue) za;
			if (incParams) {
				return indexStr + MessageFormat.format(Constant.messages
						.getString("zest.element.assign.field"), zsa
						.getVariableName(), zsa.getFieldDefinition()
						.getFormIndex(), zsa.getFieldDefinition()
						.getFieldName());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.assign.field.title");
			}

		} else if (za instanceof ZestAssignRegexDelimiters) {
			ZestAssignRegexDelimiters zsa = (ZestAssignRegexDelimiters) za;
			if (incParams) {
				return indexStr + MessageFormat.format(Constant.messages
						.getString("zest.element.assign.regex"), zsa
						.getVariableName(), zsa.getPrefix(), zsa.getPostfix());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.assign.regex.title");
			}

		} else if (za instanceof ZestAssignStringDelimiters) {
			ZestAssignStringDelimiters zsa = (ZestAssignStringDelimiters) za;
			if (incParams) {
				return indexStr + MessageFormat.format(Constant.messages
						.getString("zest.element.assign.delstring"), zsa
						.getVariableName(), zsa.getPrefix(), zsa.getPostfix());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.assign.delstring.title");
			}

		} else if (za instanceof ZestAssignRandomInteger) {
			ZestAssignRandomInteger zsa = (ZestAssignRandomInteger) za;
			if (incParams) {
				return indexStr + MessageFormat.format(Constant.messages
						.getString("zest.element.assign.rndint"), zsa
						.getVariableName(), zsa.getMinInt(), zsa.getMaxInt());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.assign.rndint.title");
			}

		} else if (za instanceof ZestAssignString) {
			ZestAssignString zsa = (ZestAssignString) za;
			if (incParams) {
				return indexStr + MessageFormat.format(Constant.messages
						.getString("zest.element.assign.string"), zsa
						.getVariableName(), zsa.getString());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.assign.string.title");
			}

		} else if (za instanceof ZestAssignReplace) {
			ZestAssignReplace zsa = (ZestAssignReplace) za;
			if (incParams) {
				return indexStr + MessageFormat.format(Constant.messages
						.getString("zest.element.assign.replace"), zsa
						.getVariableName(), zsa.getReplace(), zsa.getReplacement());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.assign.replace.title");
			}

		} else if (za instanceof ZestActionScan) {
			ZestActionScan zsa = (ZestActionScan) za;
			if (incParams) {
				return indexStr + MessageFormat
						.format(Constant.messages
								.getString("zest.element.action.scan"), zsa
								.getTargetParameter());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.action.scan.title");
			}

		} else if (za instanceof ZestActionFail) {
			ZestActionFail zsa = (ZestActionFail) za;
			if (incParams) {
				return indexStr + MessageFormat
						.format(Constant.messages
								.getString("zest.element.action.fail"), zsa
								.getMessage());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.action.fail.title");
			}
		} else if (za instanceof ZestActionIntercept) {
			// No parameters
			return indexStr + Constant.messages
					.getString("zest.element.action.intercept.title");
		} else if (za instanceof ZestActionInvoke) {
			ZestActionInvoke zsa = (ZestActionInvoke) za;
			if (incParams) {
				File f = new File(zsa.getScript());
				return indexStr + MessageFormat.format(
						Constant.messages.getString("zest.element.action.invoke"), 
						zsa.getVariableName(), f.getName());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.action.invoke.title");
			}
		} else if (za instanceof ZestActionPrint) {
			ZestActionPrint zsa = (ZestActionPrint) za;
			if (incParams) {
				return indexStr + MessageFormat
						.format(Constant.messages
								.getString("zest.element.action.print"), zsa
								.getMessage());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.action.print.title");
			}
		} else if (za instanceof ZestActionSleep) {
			ZestActionSleep zsa = (ZestActionSleep) za;
			if (incParams) {
				return indexStr + MessageFormat.format(
						Constant.messages.getString("zest.element.action.sleep"), 
						zsa.getMilliseconds());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.action.sleep.title");
			}
		} else if (za instanceof ZestComment) {
			ZestComment zsa = (ZestComment) za;
			if (incParams) {
				String comment = zsa.getComment();
				if (comment.length() > 30) {
					comment = comment.substring(0, 30) + "...";
					comment.replace("\n", " ");
				}
				return indexStr + MessageFormat.format(
						Constant.messages.getString("zest.element.comment"), 
						comment);
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.comment.title");
			}
		} else if (za instanceof ZestControlReturn) {
			ZestControlReturn zsa = (ZestControlReturn) za;
			if (incParams) {
				return indexStr + MessageFormat.format(
						Constant.messages.getString("zest.element.control.return"), 
						zsa.getValue());
			} else {
				return indexStr + Constant.messages
						.getString("zest.element.control.return.title");
			}
		} else if (za instanceof ZestControlLoopBreak) {
			return indexStr + Constant.messages.getString("zest.element.control.loopbrk.title");
		} else if (za instanceof ZestControlLoopNext) {
			return indexStr + Constant.messages.getString("zest.element.control.loopnext.title");
		}

		return indexStr + MessageFormat.format(Constant.messages
				.getString("zest.element.unknown"), za.getClass()
				.getCanonicalName());
	}

	public static String toUiFailureString(ZestAssertion za, ZestRuntime runtime) {

		if (za.getRootExpression() instanceof ZestExpressionLength) {
			ZestExpressionLength sla = (ZestExpressionLength) za
					.getRootExpression();
			int intDiff = 100;
			String var = runtime.getVariable(sla.getVariableName());
			int varLength = -1;
			if (var != null) {
				varLength = var.length();
				if (sla.getLength() == 0) {
					if (sla.getLength() == 0) {
						intDiff = 0;
					}
				} else {
					intDiff = (sla.getLength() - varLength) * 100
							/ sla.getLength();
				}
			}
			String strDiff = Integer.toString(intDiff);
			if (intDiff == 1) {
				// Show to one decimal place
				DecimalFormat df = new DecimalFormat("#.#");
				strDiff = df
						.format(((double) (sla.getLength() - varLength) * 100)
								/ sla.getLength());
			} else if (intDiff == 0) {
				// Show to two decimal place
				DecimalFormat df = new DecimalFormat("#.##");
				strDiff = df
						.format(((double) (sla.getLength() - varLength) * 100)
								/ sla.getLength());
			}
			return MessageFormat.format(
					Constant.messages.getString("zest.fail.assert.length"),
					sla.getVariableName(), sla.getLength(), varLength, strDiff);
		} else if (za.getRootExpression() instanceof ZestExpressionStatusCode) {
			ZestExpressionStatusCode sca = (ZestExpressionStatusCode) za
					.getRootExpression();
			return MessageFormat.format(
					Constant.messages.getString("zest.fail.assert.statuscode"),
					sca.getCode(), runtime.getLastResponse().getStatusCode());
		} else if (za.getRootExpression() instanceof ZestExpressionRegex) {
			ZestExpressionRegex zhr = (ZestExpressionRegex) za
					.getRootExpression();
			if (zhr.isInverse()) {
				return MessageFormat.format(Constant.messages
						.getString("zest.fail.assert.headregex.exc"), zhr
						.getRegex());
			} else {
				return MessageFormat.format(Constant.messages
						.getString("zest.fail.assert.headregex.inc"), zhr
						.getRegex());
			}
		}

		return toUiString(za, true);
	}

	public static HttpMessage toHttpMessage(ZestRequest request,
			ZestResponse response) throws URIException,
			HttpMalformedHeaderException {
		if (request == null || request.getUrl() == null) {
			return null;
		}
		HttpMessage msg = new HttpMessage(new URI(request.getUrl().toString(), false));
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
		msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

		if (response != null) {
			try {
				msg.setResponseHeader(new HttpResponseHeader(response.getHeaders()));
			} catch (Exception e) {
				log.error(e.getMessage(), e);
			}
			msg.setResponseBody(response.getBody());
			msg.setTimeElapsedMillis((int) response.getResponseTimeInMs());
		}

		return msg;
	}

	public static ZestResponse toZestResponse(HttpMessage msg)
			throws MalformedURLException {
		return new ZestResponse(new URL(msg.getRequestHeader().getURI().toString()), 
				msg.getResponseHeader().toString(), 
				msg.getResponseBody().toString(), 
				msg.getResponseHeader().getStatusCode(), 
				msg.getTimeElapsedMillis());
	}

	public static ZestRequest toZestRequest(HttpMessage msg, boolean replaceTokens)
			throws MalformedURLException, HttpMalformedHeaderException,
			SQLException {
		return toZestRequest(msg, replaceTokens, false);
	}

	public static ZestRequest toZestRequest(HttpMessage msg,
			boolean replaceTokens, boolean incAllHeaders) throws MalformedURLException,
			HttpMalformedHeaderException, SQLException {
		if (replaceTokens) {
			ZestRequest req = new ZestRequest();
			req.setMethod(msg.getRequestHeader().getMethod());
			if (msg.getRequestHeader().getURI() != null) {
				req.setUrl(new URL(msg.getRequestHeader().getURI().toString()));
			}
			req.setUrlToken(correctTokens(msg.getRequestHeader().getURI().toString()));
			
			if (incAllHeaders) {
				setAllHeaders(req, msg);
			} else {
				setHeaders(req, msg, true);
			}
			req.setData(correctTokens(msg.getRequestBody().toString()));
			req.setResponse(
					new ZestResponse(
							req.getUrl(), 
							msg.getResponseHeader().toString(), 
							msg.getResponseBody().toString(), 
							msg.getResponseHeader().getStatusCode(), 
							msg.getTimeElapsedMillis()));
			return req;

		} else {
			ZestRequest req = new ZestRequest();
			req.setUrl(new URL(msg.getRequestHeader().getURI().toString()));
			req.setMethod(msg.getRequestHeader().getMethod());
			if (incAllHeaders) {
				setAllHeaders(req, msg);
			} else {
				setHeaders(req, msg, true);
			}
			req.setData(msg.getRequestBody().toString());
			req.setResponse(new ZestResponse(req.getUrl(), msg
					.getResponseHeader().toString(), msg.getResponseBody()
					.toString(), msg.getResponseHeader().getStatusCode(), msg
					.getTimeElapsedMillis()));
			return req;
		}
	}

	private static void setHeaders(ZestRequest req, HttpMessage msg, boolean replaceTokens) {
		// TODO make the headers included be configurable
		String[] headers = msg.getRequestHeader().getHeadersAsString()
				.split(HttpHeader.CRLF);
		StringBuilder sb = new StringBuilder();
		for (String header : headers) {
			if (header.toLowerCase().startsWith(
					HttpHeader.CONTENT_TYPE.toLowerCase())) {
				sb.append(header);
				sb.append(HttpHeader.CRLF);
			}
		}
		if (replaceTokens) {
			req.setHeaders(correctTokens(sb.toString()));
		} else {
			req.setHeaders(sb.toString());
		}
	}

	private static void setAllHeaders(ZestRequest req, HttpMessage msg) {
		String[] headers = msg.getRequestHeader().getHeadersAsString()
				.split(HttpHeader.CRLF);
		StringBuilder sb = new StringBuilder();
		boolean first = true;
		for (String header : headers) {
			if (first) {
				// Drop the first one as this one will get added anyway
				first = false;
			} else {
				sb.append(header);
				sb.append(HttpHeader.CRLF);
			}
		}
		req.setHeaders(sb.toString());
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

	// public static boolean isShadow(ScriptNode node) {
	// if (node == null || node.getUserObject() == null) {
	// return false;
	// }
	// if (node.getUserObject() instanceof ZestElementWrapper) {
	// return ((ZestElementWrapper) node.getUserObject()).isShadow();
	// }
	// return false;
	// }

	public static int getShadowLevel(ScriptNode node) {
		if (node == null || node.getUserObject() == null) {
			return 0;
		}
		if (node.getUserObject() instanceof ZestElementWrapper) {
			return ((ZestElementWrapper) node.getUserObject()).getShadowLevel();
		}
		return 0;
	}

	public static MouseAdapter stdMenuAdapter() {
		return new java.awt.event.MouseAdapter() {
			@Override
			public void mousePressed(java.awt.event.MouseEvent e) {
				mouseAction(e);
			}

			@Override
			public void mouseReleased(java.awt.event.MouseEvent e) {
				mouseAction(e);
			}

			public void mouseAction(java.awt.event.MouseEvent e) {
				// right mouse button action
				if ((e.getModifiers() & InputEvent.BUTTON3_MASK) != 0
						|| e.isPopupTrigger()) {
					View.getSingleton().getPopupMenu()
							.show(e.getComponent(), e.getX(), e.getY());
				}
			}
		};
	}
	
	public static boolean isValidVariableName(String name) {
		if (name == null || name.length() == 0) {
			return false;
		}
		if (!Character.isLetter(name.charAt(0))) {
			// Seams reasonable to require it starts with a character
			return false;
		}
		for (char chr : name.toCharArray()) {
			if (!Character.isLetterOrDigit(chr) &&
					ZEST_VAR_VALID_CHRS.indexOf(chr) == -1) {
				return false;
			}
		}
		return true;
	}

	public static void setShowIndexes(boolean showIndexes) {
		ZestZapUtils.showIndexes = showIndexes;
	}
	
}
