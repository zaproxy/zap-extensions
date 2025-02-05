/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.parserapi;

import java.io.IOException;
import java.util.List;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;
import org.antlr.v4.runtime.Token;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.parserapi.impl.JavaScriptLexer;
import org.zaproxy.addon.commonlib.parserapi.impl.JavaScriptParser;

public class ParserApi {

    private static final char SINGLE_QUOTE_CHARACTER = '\'';
    private static final char DOUBLE_QUOTE_CHARACTER = '"';
    private static final char FORWARD_SLASH_CHARACTER = '/';

    public enum Context {
        NO_QUOTE,
        SINGLE_QUOTE,
        DOUBLE_QUOTE,
        SLASH_QUOTE
    }

    private String scriptCode;
    private int targetBlockNumber;

    public void getTargetScriptBlock(HttpMessage msg, String target) {
        String htmlCode = msg.getResponseBody().toString();
        Source htmlSrc = new Source(htmlCode);
        List<Element> scripts = htmlSrc.getAllElements(HTMLElementName.SCRIPT);
        for (Element ele : scripts) {
            String code = ele.getContent().toString();
            if (code.contains(target)) {
                break;
            }
            targetBlockNumber += 1;
        }
    }

    public void getTargetScriptCode(HttpMessage msg, String target) {
        String htmlCode = msg.getResponseBody().toString();
        Source htmlSrc = new Source(htmlCode);
        scriptCode =
                htmlSrc.getAllElements(HTMLElementName.SCRIPT)
                        .get(targetBlockNumber)
                        .getContent()
                        .toString();
    }

    public boolean parseScript() throws IOException {
        CharStream charStream = CharStreams.fromString(scriptCode);
        JavaScriptLexer jsLexer = new JavaScriptLexer(charStream);
        CommonTokenStream cts = new CommonTokenStream(jsLexer);
        JavaScriptParser jsParser = new JavaScriptParser(cts);
        jsParser.removeErrorListeners();
        jsParser.addErrorListener(ThrowOnSyntaxErrorListener.INSTANCE);

        try {
            jsParser.program();
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public boolean inExecutionContext(String target) throws IOException {
        CharStream charStream = CharStreams.fromString(scriptCode);
        JavaScriptLexer jsLexer = new JavaScriptLexer(charStream);

        Token token = jsLexer.nextToken();
        while (token.getType() != -1) {
            if (token.getType() == JavaScriptLexer.Identifier && token.getText().equals(target)) {
                return true;
            }
            token = jsLexer.nextToken();
        }

        return false;
    }

    public Context getContext(String target) throws IOException {
        CharStream charStream = CharStreams.fromString(scriptCode);
        JavaScriptLexer jsLexer = new JavaScriptLexer(charStream);

        Token token = jsLexer.nextToken();
        while (token.getType() != -1) {
            String tokenText = token.getText();
            if (tokenText.contains(target)) {
                switch (tokenText.charAt(0)) {
                    case DOUBLE_QUOTE_CHARACTER:
                        return Context.DOUBLE_QUOTE;
                    case SINGLE_QUOTE_CHARACTER:
                        return Context.SINGLE_QUOTE;
                    case FORWARD_SLASH_CHARACTER:
                        return Context.SLASH_QUOTE;
                    default:
                        return Context.NO_QUOTE;
                }
            }

            token = jsLexer.nextToken();
        }

        return Context.NO_QUOTE;
    }

    private static class ThrowOnSyntaxErrorListener extends BaseErrorListener {

        static final ThrowOnSyntaxErrorListener INSTANCE = new ThrowOnSyntaxErrorListener();

        // Reuse the exception, used just for control flow.
        private static final RuntimeException SYNTAX_EXCEPTION =
                new IllegalArgumentException("Syntax Error");

        private ThrowOnSyntaxErrorListener() {}

        @Override
        public void syntaxError(
                Recognizer<?, ?> recognizer,
                Object offendingSymbol,
                int line,
                int charPositionInLine,
                String msg,
                RecognitionException e) {
            throw SYNTAX_EXCEPTION;
        }
    }
}
