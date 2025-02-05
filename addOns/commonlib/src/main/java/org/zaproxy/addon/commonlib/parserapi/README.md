## JavaScript Parser

The JavaScript parser used in this add-on is generated using ANTLR with their [JavaScript grammar](https://github.com/antlr/grammars-v4/blob/14fc51dfd712a99663497035f1f63fa8eac1a225/javascript/javascript/).

The following files were copied from the referenced repository:
 - [`JavaScriptLexerBase.java`](src/main/java/org/zaproxy/addon/commonlib/parserapi/impl/JavaScriptLexerBase.java);
 - [`JavaScriptParserBase.java`](src/main/java/org/zaproxy/addon/commonlib/parserapi/impl/JavaScriptParserBase.java);
 - [`JavaScriptLexer.g4`](src/main/antlr/org/zaproxy/addon/commonlib/parserapi/impl/JavaScriptLexer.g4);
 - [`JavaScriptParser.g4`](src/main/antlr/org/zaproxy/addon/commonlib/parserapi/impl/JavaScriptParser.g4).

The parser is automatically generated when the code is compiled through the [`antlr` Gradle plugin](https://docs.gradle.org/current/userguide/antlr_plugin.html).
