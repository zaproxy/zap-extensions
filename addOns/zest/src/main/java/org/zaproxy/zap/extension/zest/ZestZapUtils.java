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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.zest;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JPopupMenu;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zest.core.v1.ZestActionFail;
import org.zaproxy.zest.core.v1.ZestActionGlobalVariableRemove;
import org.zaproxy.zest.core.v1.ZestActionGlobalVariableSet;
import org.zaproxy.zest.core.v1.ZestActionIntercept;
import org.zaproxy.zest.core.v1.ZestActionInvoke;
import org.zaproxy.zest.core.v1.ZestActionPrint;
import org.zaproxy.zest.core.v1.ZestActionScan;
import org.zaproxy.zest.core.v1.ZestActionSleep;
import org.zaproxy.zest.core.v1.ZestAssertion;
import org.zaproxy.zest.core.v1.ZestAssignCalc;
import org.zaproxy.zest.core.v1.ZestAssignFieldValue;
import org.zaproxy.zest.core.v1.ZestAssignFromElement;
import org.zaproxy.zest.core.v1.ZestAssignGlobalVariable;
import org.zaproxy.zest.core.v1.ZestAssignRandomInteger;
import org.zaproxy.zest.core.v1.ZestAssignRegexDelimiters;
import org.zaproxy.zest.core.v1.ZestAssignReplace;
import org.zaproxy.zest.core.v1.ZestAssignString;
import org.zaproxy.zest.core.v1.ZestAssignStringDelimiters;
import org.zaproxy.zest.core.v1.ZestClientAssignCookie;
import org.zaproxy.zest.core.v1.ZestClientElementAssign;
import org.zaproxy.zest.core.v1.ZestClientElementClear;
import org.zaproxy.zest.core.v1.ZestClientElementClick;
import org.zaproxy.zest.core.v1.ZestClientElementSendKeys;
import org.zaproxy.zest.core.v1.ZestClientElementSubmit;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestClientScreenshot;
import org.zaproxy.zest.core.v1.ZestClientSwitchToFrame;
import org.zaproxy.zest.core.v1.ZestClientWindowClose;
import org.zaproxy.zest.core.v1.ZestClientWindowHandle;
import org.zaproxy.zest.core.v1.ZestClientWindowOpenUrl;
import org.zaproxy.zest.core.v1.ZestComment;
import org.zaproxy.zest.core.v1.ZestConditional;
import org.zaproxy.zest.core.v1.ZestControlLoopBreak;
import org.zaproxy.zest.core.v1.ZestControlLoopNext;
import org.zaproxy.zest.core.v1.ZestControlReturn;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestExpressionAnd;
import org.zaproxy.zest.core.v1.ZestExpressionClientElementExists;
import org.zaproxy.zest.core.v1.ZestExpressionEquals;
import org.zaproxy.zest.core.v1.ZestExpressionIsInteger;
import org.zaproxy.zest.core.v1.ZestExpressionLength;
import org.zaproxy.zest.core.v1.ZestExpressionOr;
import org.zaproxy.zest.core.v1.ZestExpressionRegex;
import org.zaproxy.zest.core.v1.ZestExpressionResponseTime;
import org.zaproxy.zest.core.v1.ZestExpressionStatusCode;
import org.zaproxy.zest.core.v1.ZestExpressionURL;
import org.zaproxy.zest.core.v1.ZestLoopClientElements;
import org.zaproxy.zest.core.v1.ZestLoopFile;
import org.zaproxy.zest.core.v1.ZestLoopInteger;
import org.zaproxy.zest.core.v1.ZestLoopRegex;
import org.zaproxy.zest.core.v1.ZestLoopString;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestResponse;
import org.zaproxy.zest.core.v1.ZestRuntime;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;
import org.zaproxy.zest.core.v1.ZestVariables;

public class ZestZapUtils {

    private static final String ZEST_VAR_VALID_CHRS = "-:.";

    private static final Logger log = Logger.getLogger(ZestZapUtils.class);

    /**
     * A map to convert labels to calc operations.
     *
     * @see #labelToCalcOperation(String)
     */
    private static Map<String, String> labelsToCalcOperation;

    // Only use for debugging for now, as the tree wont be fully updated if indexes change
    private static boolean showIndexes = false;

    private static JPopupMenu popupMenu;

    public static String toUiString(ZestElement za) {
        return toUiString(za, true, 0);
    }

    public static String toUiString(ZestElement za, boolean incParams) {
        return toUiString(za, incParams, 0);
    }

    public static String toUiString(ZestElement za, boolean incParams, int shadowLevel) {
        String indexStr = "";
        if (showIndexes && za instanceof ZestStatement) {
            indexStr = ((ZestStatement) za).getIndex() + ": ";
        }

        if (za instanceof ZestScript) {
            ZestScript zs = (ZestScript) za;
            return indexStr + Constant.messages.getString("zest.element.script", zs.getTitle());
        } else if (za instanceof ZestRequest) {
            ZestRequest zr = (ZestRequest) za;
            if (zr.getUrl() != null) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.request", zr.getMethod(), zr.getUrl());
            } else {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.request", zr.getMethod(), zr.getUrlToken());
            }
        } else if (za instanceof ZestResponse) {
            ZestResponse zr = (ZestResponse) za;
            return indexStr
                    + Constant.messages.getString("zest.element.response", zr.getStatusCode());

        } else if (za instanceof ZestAssertion) {
            ZestAssertion zas = (ZestAssertion) za;
            return indexStr
                    + Constant.messages.getString(
                            "zest.element.assert",
                            toUiString(
                                    (ZestElement) zas.getRootExpression(), incParams, shadowLevel));

        } else if (za instanceof ZestConditional) {
            ZestConditional zac = (ZestConditional) za;
            if (shadowLevel == 0) {
                if (zac.getRootExpression() != null) {
                    return indexStr
                            + Constant.messages.getString("zest.element.conditional.if")
                            + toUiString((ZestElement) zac.getRootExpression(), false, 0);
                } else {
                    return indexStr
                            + Constant.messages.getString("zest.element.conditional.if")
                            + " ";
                }
            } else if (shadowLevel == 1) {
                return indexStr + Constant.messages.getString("zest.element.conditional.then");
            } else {
                return indexStr + Constant.messages.getString("zest.element.conditional.else");
                //				if (zac.getRootExpression() != null) {
                //					return indexStr + Constant.messages.getString(
                //							"zest.element.conditional.else",
                //							toUiString((ZestElement) zac.getRootExpression(), incParams, shadowLevel));
                //				} else {
                //					return indexStr +
                // Constant.messages.getString("zest.element.conditional.else", "");
                //				}
            }
        } else if (za instanceof ZestExpressionAnd) {
            return indexStr + Constant.messages.getString("zest.element.expression.and", incParams);
        } else if (za instanceof ZestExpressionOr) {
            return indexStr + Constant.messages.getString("zest.element.expression.or", incParams);
        } else if (za instanceof ZestExpressionStatusCode) {
            ZestExpressionStatusCode sca = (ZestExpressionStatusCode) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.expression.statuscode", sca.getCode());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.expression.statuscode.title");
            }
        } else if (za instanceof ZestExpressionLength) {
            ZestExpressionLength sla = (ZestExpressionLength) za;
            if (incParams) {
                String key =
                        sla.isInverse()
                                ? "zest.element.expression.length.inverse"
                                : "zest.element.expression.length";
                return indexStr
                        + Constant.messages.getString(
                                key, sla.getVariableName(), sla.getLength(), sla.getApprox());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.expression.length.title");
            }
        } else if (za instanceof ZestExpressionResponseTime) {
            ZestExpressionResponseTime zhr = (ZestExpressionResponseTime) za;
            if (incParams) {
                if (zhr.isGreaterThan()) {
                    return indexStr
                            + Constant.messages.getString(
                                    "zest.element.expression.resptimegt", zhr.getTimeInMs());
                } else {
                    return indexStr
                            + Constant.messages.getString(
                                    "zest.element.expression.resptimelt", zhr.getTimeInMs());
                }
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.expression.resptime.title");
            }
        } else if (za instanceof ZestExpressionRegex) {
            // TODO case exact
            // TODO what about exp inverse ??
            ZestExpressionRegex zer = (ZestExpressionRegex) za;
            if (incParams) {
                if (zer.isInverse()) {
                    return indexStr
                            + Constant.messages.getString(
                                    "zest.element.expression.regex.exc",
                                    zer.getVariableName(),
                                    zer.getRegex());
                } else {
                    return indexStr
                            + Constant.messages.getString(
                                    "zest.element.expression.regex.inc",
                                    zer.getVariableName(),
                                    zer.getRegex());
                }
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.expression.regex.title");
            }
        } else if (za instanceof ZestExpressionEquals) {
            // TODO case exact
            ZestExpressionEquals zer = (ZestExpressionEquals) za;
            if (incParams) {
                String key =
                        zer.isInverse()
                                ? "zest.element.expression.equals.inverse"
                                : "zest.element.expression.equals";
                return indexStr
                        + Constant.messages.getString(key, zer.getVariableName(), zer.getValue());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.expression.equals.title");
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
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.expression.url", incStr, excStr);
            } else {
                return indexStr + Constant.messages.getString("zest.element.expression.url.title");
            }

        } else if (za instanceof ZestExpressionIsInteger) {
            ZestExpressionIsInteger zer = (ZestExpressionIsInteger) za;
            if (incParams) {
                String key =
                        zer.isInverse()
                                ? "zest.element.expression.isint.inverse"
                                : "zest.element.expression.isint";
                return indexStr + Constant.messages.getString(key, zer.getVariableName());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.expression.isint.title");
            }

        } else if (za instanceof ZestExpressionClientElementExists) {
            ZestExpressionClientElementExists sla = (ZestExpressionClientElementExists) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.expression.clientelement",
                                sla.getWindowHandle(),
                                sla.getType(),
                                sla.getElement());
            } else {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.expression.clientelement.title");
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

                return indexStr
                        + Constant.messages.getString(
                                "zest.element.loop.string",
                                zals.getVariableName(),
                                vals.toString());
            } else {
                return indexStr + Constant.messages.getString("zest.element.loop.string.title");
            }
        } else if (za instanceof ZestLoopFile) {
            ZestLoopFile zalf = (ZestLoopFile) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.loop.file",
                                zalf.getVariableName(),
                                zalf.getFile().getName());
            } else {
                return indexStr + Constant.messages.getString("zest.element.loop.file.title");
            }
        } else if (za instanceof ZestLoopInteger) {
            ZestLoopInteger zali = (ZestLoopInteger) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.loop.integer",
                                zali.getVariableName(),
                                zali.getStart(),
                                zali.getEnd(),
                                zali.getStep());
            } else {
                return indexStr + Constant.messages.getString("zest.element.loop.integer.title");
            }
        } else if (za instanceof ZestLoopClientElements) {
            ZestLoopClientElements zalce = (ZestLoopClientElements) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.loop.clientElements",
                                zalce.getVariableName(),
                                zalce.getWindowHandle(),
                                zalce.getType(),
                                zalce.getElement(),
                                zalce.getAttribute());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.loop.clientElements.title");
            }
        } else if (za instanceof ZestLoopRegex) {
            ZestLoopRegex zalr = (ZestLoopRegex) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.loop.regex",
                                zalr.getVariableName(),
                                zalr.getInputVariableName(),
                                zalr.getRegex());
            } else {
                return indexStr + Constant.messages.getString("zest.element.loop.regex.title");
            }
        } else if (za instanceof ZestAssignFieldValue) {
            ZestAssignFieldValue zsa = (ZestAssignFieldValue) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.assign.field",
                                zsa.getVariableName(),
                                zsa.getFieldDefinition().getFormIndex(),
                                zsa.getFieldDefinition().getFieldName());
            } else {
                return indexStr + Constant.messages.getString("zest.element.assign.field.title");
            }

        } else if (za instanceof ZestAssignRegexDelimiters) {
            ZestAssignRegexDelimiters zsa = (ZestAssignRegexDelimiters) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.assign.regex",
                                zsa.getVariableName(),
                                zsa.getPrefix(),
                                zsa.getPostfix());
            } else {
                return indexStr + Constant.messages.getString("zest.element.assign.regex.title");
            }

        } else if (za instanceof ZestAssignStringDelimiters) {
            ZestAssignStringDelimiters zsa = (ZestAssignStringDelimiters) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.assign.delstring",
                                zsa.getVariableName(),
                                zsa.getPrefix(),
                                zsa.getPostfix());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.assign.delstring.title");
            }

        } else if (za instanceof ZestAssignRandomInteger) {
            ZestAssignRandomInteger zsa = (ZestAssignRandomInteger) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.assign.rndint",
                                zsa.getVariableName(),
                                zsa.getMinInt(),
                                zsa.getMaxInt());
            } else {
                return indexStr + Constant.messages.getString("zest.element.assign.rndint.title");
            }

        } else if (za instanceof ZestAssignString) {
            ZestAssignString zsa = (ZestAssignString) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.assign.string",
                                zsa.getVariableName(),
                                zsa.getString());
            } else {
                return indexStr + Constant.messages.getString("zest.element.assign.string.title");
            }

        } else if (za instanceof ZestAssignReplace) {
            ZestAssignReplace zsa = (ZestAssignReplace) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.assign.replace",
                                zsa.getVariableName(),
                                zsa.getReplace(),
                                zsa.getReplacement());
            } else {
                return indexStr + Constant.messages.getString("zest.element.assign.replace.title");
            }

        } else if (za instanceof ZestAssignCalc) {
            ZestAssignCalc zsa = (ZestAssignCalc) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.assign.calc",
                                zsa.getVariableName(),
                                zsa.getOperandA(),
                                calcOperationToLabel(zsa.getOperation()),
                                zsa.getOperandB());
            } else {
                return indexStr + Constant.messages.getString("zest.element.assign.calc.title");
            }
        } else if (za instanceof ZestAssignFromElement) {
            ZestAssignFromElement zsa = (ZestAssignFromElement) za;
            if (incParams) {

                StringBuilder sb = new StringBuilder();
                if (!zsa.isFilteredByElementName() && !zsa.isFilteredByAttribute()) {
                    sb.append(
                            Constant.messages.getString(
                                    "zest.element.assign.fromElement.elements"));
                    sb.append("()");
                }

                if (zsa.isFilteredByElementName() || zsa.isFilteredByAttribute()) {
                    sb.append(Constant.messages.getString("zest.element.assign.fromElement.where"));
                    sb.append('(');
                }

                if (zsa.isFilteredByElementName()) {
                    sb.append(
                            Constant.messages.getString("zest.element.assign.fromElement.element"));
                    sb.append(" == '");
                    sb.append(zsa.getElementNameFilter());
                    sb.append('\'');
                }

                if (zsa.isFilteredByElementName() && zsa.isFilteredByAttribute()) {
                    sb.append(" && ");
                }

                if (zsa.isFilteredByAttribute()) {
                    sb.append(
                            Constant.messages.getString(
                                    "zest.element.assign.fromElement.attributes"));
                    sb.append("['");
                    sb.append(zsa.getAttributeNameFilter());
                    sb.append("'] ");
                    sb.append(Constant.messages.getString("zest.element.assign.fromElement.match"));
                    sb.append(" '");
                    sb.append(zsa.getAttributeValueFilter());
                    sb.append('\'');
                }

                if (zsa.isFilteredByElementName() || zsa.isFilteredByAttribute()) {
                    sb.append(')');
                }

                if (zsa.areFilteredElementsReversed()) {
                    sb.append('.');
                    sb.append(
                            Constant.messages.getString("zest.element.assign.fromElement.reverse"));
                    sb.append("()");
                }

                sb.append('[');
                sb.append(zsa.getElementIndex());
                sb.append(']');

                if (zsa.isReturningElement()) {
                    sb.append('.');
                    sb.append(
                            Constant.messages.getString(
                                    "zest.element.assign.fromElement.selectcontent"));
                    sb.append("()");
                }

                if (zsa.isReturningAttribute()) {
                    sb.append('.');
                    sb.append(
                            Constant.messages.getString(
                                    "zest.element.assign.fromElement.selectattribute"));
                    sb.append("('");
                    sb.append(zsa.getReturnedAttributeName());
                    sb.append("')");
                }

                return indexStr
                        + Constant.messages.getString(
                                "zest.element.assign.fromElement",
                                zsa.getVariableName(),
                                sb.toString());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.assign.fromElement.title");
            }

        } else if (za instanceof ZestAssignGlobalVariable) {
            ZestAssignGlobalVariable zagv = (ZestAssignGlobalVariable) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.assign.globalvar",
                                zagv.getVariableName(),
                                zagv.getGlobalVariableName());
            }
            return indexStr + Constant.messages.getString("zest.element.assign.globalvar.title");
        } else if (za instanceof ZestActionScan) {
            ZestActionScan zsa = (ZestActionScan) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.action.scan", zsa.getTargetParameter());
            } else {
                return indexStr + Constant.messages.getString("zest.element.action.scan.title");
            }

        } else if (za instanceof ZestActionFail) {
            ZestActionFail zsa = (ZestActionFail) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString("zest.element.action.fail", zsa.getMessage());
            } else {
                return indexStr + Constant.messages.getString("zest.element.action.fail.title");
            }
        } else if (za instanceof ZestActionIntercept) {
            // No parameters
            return indexStr + Constant.messages.getString("zest.element.action.intercept.title");
        } else if (za instanceof ZestActionInvoke) {
            ZestActionInvoke zsa = (ZestActionInvoke) za;
            if (incParams) {
                File f = new File(zsa.getScript());
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.action.invoke", zsa.getVariableName(), f.getName());
            } else {
                return indexStr + Constant.messages.getString("zest.element.action.invoke.title");
            }
        } else if (za instanceof ZestActionPrint) {
            ZestActionPrint zsa = (ZestActionPrint) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.action.print", zsa.getMessage());
            } else {
                return indexStr + Constant.messages.getString("zest.element.action.print.title");
            }
        } else if (za instanceof ZestActionSleep) {
            ZestActionSleep zsa = (ZestActionSleep) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.action.sleep", zsa.getMilliseconds());
            } else {
                return indexStr + Constant.messages.getString("zest.element.action.sleep.title");
            }
        } else if (za instanceof ZestActionGlobalVariableSet) {
            ZestActionGlobalVariableSet zagvs = (ZestActionGlobalVariableSet) za;
            if (incParams) {
                String value = zagvs.getValue();
                if (value.length() > 10) {
                    value = value.substring(0, 10) + "...";
                }
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.action.globalvarset",
                                zagvs.getGlobalVariableName(),
                                value);
            }
            return indexStr + Constant.messages.getString("zest.element.action.globalvarset.title");
        } else if (za instanceof ZestActionGlobalVariableRemove) {
            ZestActionGlobalVariableRemove zagvr = (ZestActionGlobalVariableRemove) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.action.globalvarremove",
                                zagvr.getGlobalVariableName());
            }
            return indexStr
                    + Constant.messages.getString("zest.element.action.globalvarremove.title");
        } else if (za instanceof ZestComment) {
            ZestComment zsa = (ZestComment) za;
            if (incParams) {
                String comment = zsa.getComment();
                if (comment.length() > 30) {
                    comment = comment.substring(0, 30) + "...";
                    comment.replace("\n", " ");
                }
                return indexStr + Constant.messages.getString("zest.element.comment", comment);
            } else {
                return indexStr + Constant.messages.getString("zest.element.comment.title");
            }
        } else if (za instanceof ZestControlReturn) {
            ZestControlReturn zsa = (ZestControlReturn) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.control.return", zsa.getValue());
            } else {
                return indexStr + Constant.messages.getString("zest.element.control.return.title");
            }
        } else if (za instanceof ZestControlLoopBreak) {
            return indexStr + Constant.messages.getString("zest.element.control.loopbrk.title");
        } else if (za instanceof ZestControlLoopNext) {
            return indexStr + Constant.messages.getString("zest.element.control.loopnext.title");
        } else if (za instanceof ZestClientAssignCookie) {
            ZestClientAssignCookie zcl = (ZestClientAssignCookie) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientAssignCookie",
                                zcl.getWindowHandle(),
                                zcl.getVariableName(),
                                zcl.getCookieName());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.clientAssignCookie.title");
            }
        } else if (za instanceof ZestClientLaunch) {
            ZestClientLaunch zcl = (ZestClientLaunch) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientLaunch",
                                zcl.getWindowHandle(),
                                zcl.getBrowserType(),
                                zcl.getUrl());
            } else {
                return indexStr + Constant.messages.getString("zest.element.clientLaunch.title");
            }
        } else if (za instanceof ZestClientElementAssign) {
            ZestClientElementAssign zcl = (ZestClientElementAssign) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientElementAssign",
                                zcl.getWindowHandle(),
                                zcl.getType(),
                                zcl.getElement());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.clientElementAssign.title");
            }
        } else if (za instanceof ZestClientElementClear) {
            ZestClientElementClear zcl = (ZestClientElementClear) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientElementClear",
                                zcl.getWindowHandle(),
                                zcl.getType(),
                                zcl.getElement());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.clientElementClear.title");
            }
        } else if (za instanceof ZestClientElementClick) {
            ZestClientElementClick zcl = (ZestClientElementClick) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientElementClick",
                                zcl.getWindowHandle(),
                                zcl.getType(),
                                zcl.getElement());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.clientElementClick.title");
            }
        } else if (za instanceof ZestClientElementSendKeys) {
            ZestClientElementSendKeys zcl = (ZestClientElementSendKeys) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientElementSendKeys",
                                zcl.getWindowHandle(),
                                zcl.getType(),
                                zcl.getElement(),
                                zcl.getValue());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.clientElementSendKeys.title");
            }
        } else if (za instanceof ZestClientElementSubmit) {
            ZestClientElementSubmit zcl = (ZestClientElementSubmit) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientElementSubmit",
                                zcl.getWindowHandle(),
                                zcl.getType(),
                                zcl.getElement());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.clientElementSubmit.title");
            }
        } else if (za instanceof ZestClientScreenshot) {
            ZestClientScreenshot zcs = (ZestClientScreenshot) za;
            if (!incParams) {
                return indexStr
                        + Constant.messages.getString("zest.element.clientScreenshot.title");
            }

            String varName = zcs.getVariableName();
            String fileName = extractFileName(zcs.getFilePath());
            if (varName == null || varName.isEmpty()) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientScreenshot.file",
                                zcs.getWindowHandle(),
                                fileName);
            }

            if (fileName.isEmpty()) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientScreenshot.var",
                                zcs.getWindowHandle(),
                                varName);
            }

            return indexStr
                    + Constant.messages.getString(
                            "zest.element.clientScreenshot.filevar",
                            zcs.getWindowHandle(),
                            fileName,
                            varName);
        } else if (za instanceof ZestClientSwitchToFrame) {
            ZestClientSwitchToFrame zcl = (ZestClientSwitchToFrame) za;
            if (incParams) {
                String frame;
                if (zcl.getFrameIndex() >= 0) {
                    frame = Integer.toString(zcl.getFrameIndex());
                } else if (zcl.isParent()) {
                    frame = Constant.messages.getString("zest.element.clientSwitchToFrame.parent");
                } else {
                    frame = zcl.getFrameName();
                }
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientSwitchToFrame", zcl.getWindowHandle(), frame);
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.clientSwitchToFrame.title");
            }
        } else if (za instanceof ZestClientWindowHandle) {
            ZestClientWindowHandle zcl = (ZestClientWindowHandle) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientWindowHandle",
                                zcl.getWindowHandle(),
                                zcl.getUrl());
            } else {
                return indexStr + Constant.messages.getString("zest.element.clientWindow.title");
            }
        } else if (za instanceof ZestClientWindowClose) {
            ZestClientWindowClose zcl = (ZestClientWindowClose) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientWindowClose", zcl.getWindowHandle());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.clientWindowClose.title");
            }
        } else if (za instanceof ZestClientWindowOpenUrl) {
            ZestClientWindowOpenUrl zcl = (ZestClientWindowOpenUrl) za;
            if (incParams) {
                return indexStr
                        + Constant.messages.getString(
                                "zest.element.clientWindowOpenUrl",
                                zcl.getWindowHandle(),
                                zcl.getUrl());
            } else {
                return indexStr
                        + Constant.messages.getString("zest.element.clientWindowOpenUrl.title");
            }
        }

        return indexStr
                + Constant.messages.getString(
                        "zest.element.unknown", za.getClass().getCanonicalName());
    }

    private static String extractFileName(String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            return "";
        }

        Path file;
        try {
            file = Paths.get(filePath);
        } catch (InvalidPathException e) {
            log.warn("Failed to parse the file path: " + filePath, e);
            return "";
        }

        Path fileName = file.getFileName();
        if (fileName == null) {
            return "";
        }
        return fileName.toString();
    }

    public static String toUiFailureString(ZestAssertion za, ZestRuntime runtime) {

        if (za.getRootExpression() instanceof ZestExpressionLength) {
            ZestExpressionLength sla = (ZestExpressionLength) za.getRootExpression();
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
                    intDiff = (sla.getLength() - varLength) * 100 / sla.getLength();
                }
            }
            String strDiff = Integer.toString(intDiff);
            if (intDiff == 1) {
                // Show to one decimal place
                DecimalFormat df = new DecimalFormat("#.#");
                strDiff =
                        df.format(((double) (sla.getLength() - varLength) * 100) / sla.getLength());
            } else if (intDiff == 0) {
                // Show to two decimal place
                DecimalFormat df = new DecimalFormat("#.##");
                strDiff =
                        df.format(((double) (sla.getLength() - varLength) * 100) / sla.getLength());
            }
            return Constant.messages.getString(
                    "zest.fail.assert.length",
                    sla.getVariableName(),
                    sla.getLength(),
                    varLength,
                    strDiff);
        } else if (za.getRootExpression() instanceof ZestExpressionStatusCode) {
            ZestExpressionStatusCode sca = (ZestExpressionStatusCode) za.getRootExpression();
            return Constant.messages.getString(
                    "zest.fail.assert.statuscode",
                    sca.getCode(),
                    runtime.getLastResponse().getStatusCode());
        } else if (za.getRootExpression() instanceof ZestExpressionRegex) {
            ZestExpressionRegex zhr = (ZestExpressionRegex) za.getRootExpression();
            switch (zhr.getVariableName()) {
                case ZestVariables.REQUEST_BODY:
                case ZestVariables.RESPONSE_BODY:
                    return getFailedAssertMessage("body", zhr.isInverse(), zhr.getRegex());
                case ZestVariables.REQUEST_HEADER:
                case ZestVariables.RESPONSE_HEADER:
                    return getFailedAssertMessage("head", zhr.isInverse(), zhr.getRegex());
                default:
                    return getFailedAssertMessage(
                            "var", zhr.isInverse(), zhr.getVariableName(), zhr.getRegex());
            }
        }

        return toUiString(za, true);
    }

    private static String getFailedAssertMessage(
            String varLocation, boolean inverse, Object... messageArgs) {
        if (inverse) {
            return Constant.messages.getString(
                    "zest.fail.assert." + varLocation + "regex.exc", messageArgs);
        }
        return Constant.messages.getString(
                "zest.fail.assert." + varLocation + "regex.inc", messageArgs);
    }

    public static HttpMessage toHttpMessage(ZestRequest request, ZestResponse response)
            throws URIException, HttpMalformedHeaderException {
        if (request == null || request.getUrl() == null) {
            return null;
        }
        HttpMessage msg = new HttpMessage(new URI(request.getUrl().toString(), false));
        msg.setTimeSentMillis(request.getTimestamp());
        if (request.getHeaders() != null) {
            try {
                msg.setRequestHeader(
                        msg.getRequestHeader().getPrimeHeader() + "\r\n" + request.getHeaders());
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

    public static ZestResponse toZestResponse(HttpMessage msg) throws MalformedURLException {
        return new ZestResponse(
                new URL(msg.getRequestHeader().getURI().toString()),
                msg.getResponseHeader().toString(),
                msg.getResponseBody().toString(),
                msg.getResponseHeader().getStatusCode(),
                msg.getTimeElapsedMillis());
    }

    public static ZestRequest toZestRequest(
            HttpMessage msg, boolean replaceTokens, ZestParam params)
            throws MalformedURLException, HttpMalformedHeaderException, SQLException {
        return toZestRequest(msg, replaceTokens, false, params);
    }

    public static ZestRequest toZestRequest(
            HttpMessage msg, boolean replaceTokens, boolean incAllHeaders, ZestParam params)
            throws MalformedURLException, HttpMalformedHeaderException, SQLException {
        if (replaceTokens) {
            ZestRequest req = new ZestRequest();
            req.setTimestamp(msg.getTimeSentMillis());
            req.setMethod(msg.getRequestHeader().getMethod());
            if (msg.getRequestHeader().getURI() != null) {
                req.setUrl(new URL(msg.getRequestHeader().getURI().toString()));
            }
            req.setUrlToken(correctTokens(msg.getRequestHeader().getURI().toString()));

            if (incAllHeaders) {
                setAllHeaders(req, msg);
            } else {
                setHeaders(req, msg, true, params.getIgnoredHeaders());
            }
            req.setData(correctTokens(msg.getRequestBody().toString()));
            req.setFollowRedirects(false);
            if (params.isIncludeResponses()) {
                req.setResponse(
                        new ZestResponse(
                                req.getUrl(),
                                msg.getResponseHeader().toString(),
                                msg.getResponseBody().toString(),
                                msg.getResponseHeader().getStatusCode(),
                                msg.getTimeElapsedMillis()));
            }
            return req;

        } else {
            ZestRequest req = new ZestRequest();
            req.setTimestamp(msg.getTimeSentMillis());
            req.setUrl(new URL(msg.getRequestHeader().getURI().toString()));
            req.setMethod(msg.getRequestHeader().getMethod());
            if (incAllHeaders) {
                setAllHeaders(req, msg);
            } else {
                setHeaders(req, msg, true, params.getIgnoredHeaders());
            }
            req.setData(msg.getRequestBody().toString());
            req.setFollowRedirects(false);
            if (params.isIncludeResponses()) {
                req.setResponse(
                        new ZestResponse(
                                req.getUrl(),
                                msg.getResponseHeader().toString(),
                                msg.getResponseBody().toString(),
                                msg.getResponseHeader().getStatusCode(),
                                msg.getTimeElapsedMillis()));
            }
            return req;
        }
    }

    private static void setHeaders(
            ZestRequest req, HttpMessage msg, boolean replaceTokens, List<String> ignoreHeaders) {
        String[] headers = msg.getRequestHeader().getHeadersAsString().split(HttpHeader.CRLF);
        StringBuilder sb = new StringBuilder();
        for (String header : headers) {
            boolean inc = true;
            for (String ignore : ignoreHeaders) {
                if (header.toLowerCase().startsWith(ignore.toLowerCase())) {
                    inc = false;
                    break;
                }
            }
            if (inc) {
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
        req.setHeaders(msg.getRequestHeader().getHeadersAsString());
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
        log.debug(
                "getElement "
                        + node.getNodeName()
                        + " Unrecognised class: "
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

    public static boolean isValidVariableName(String name) {
        if (name == null || name.length() == 0) {
            return false;
        }
        if (!Character.isLetter(name.charAt(0))) {
            // Seams reasonable to require it starts with a character
            return false;
        }
        for (char chr : name.toCharArray()) {
            if (!Character.isLetterOrDigit(chr) && ZEST_VAR_VALID_CHRS.indexOf(chr) == -1) {
                return false;
            }
        }
        return true;
    }

    public static void setShowIndexes(boolean showIndexes) {
        ZestZapUtils.showIndexes = showIndexes;
    }

    /**
     * Gets the label for the given calc operation.
     *
     * <p>If the given operation is {@code null} it returns the label of the default operation
     * (addition).
     *
     * @param operation the calc operation.
     * @return the label of the operation.
     * @see ZestAssignCalc
     * @see #labelToCalcOperation(String)
     */
    public static String calcOperationToLabel(String operation) {
        if (operation == null) {
            return Constant.messages.getString("zest.dialog.assign.oper.add");
        }

        switch (operation) {
            case ZestAssignCalc.OPERAND_ADD:
            default:
                return Constant.messages.getString("zest.dialog.assign.oper.add");
            case ZestAssignCalc.OPERAND_SUBTRACT:
                return Constant.messages.getString("zest.dialog.assign.oper.subtract");
            case ZestAssignCalc.OPERAND_MULTIPLY:
                return Constant.messages.getString("zest.dialog.assign.oper.multiply");
            case ZestAssignCalc.OPERAND_DIVIDE:
                return Constant.messages.getString("zest.dialog.assign.oper.divide");
        }
    }

    /**
     * Gets the calc operation for the given label.
     *
     * @param label the label of the operation.
     * @return the calc operation.
     * @see ZestAssignCalc
     * @see #calcOperationToLabel(String)
     */
    public static String labelToCalcOperation(String label) {
        if (labelsToCalcOperation == null) {
            labelsToCalcOperation = new HashMap<>();
            labelsToCalcOperation.put(
                    Constant.messages.getString("zest.dialog.assign.oper.add"),
                    ZestAssignCalc.OPERAND_ADD);
            labelsToCalcOperation.put(
                    Constant.messages.getString("zest.dialog.assign.oper.subtract"),
                    ZestAssignCalc.OPERAND_SUBTRACT);
            labelsToCalcOperation.put(
                    Constant.messages.getString("zest.dialog.assign.oper.multiply"),
                    ZestAssignCalc.OPERAND_MULTIPLY);
            labelsToCalcOperation.put(
                    Constant.messages.getString("zest.dialog.assign.oper.divide"),
                    ZestAssignCalc.OPERAND_DIVIDE);
        }
        return labelsToCalcOperation.get(label);
    }
}
