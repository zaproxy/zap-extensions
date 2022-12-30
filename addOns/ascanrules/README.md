## JavaScript Parser

The JavaScript parser used in the scan rules is generated using ANTLR with their [JavaScript grammar](https://github.com/antlr/grammars-v4/tree/c74f54c0893fa81c18ca9085034287d9aa9f2d93/javascript/javascript).

The following files were copied from the referenced repository:
 - [`JavaScriptLexerBase.java`](src/main/java/org/zaproxy/zap/extension/ascanrules/parserapi/impl/JavaScriptLexerBase.java), with wildcard imports removed;
 - [`JavaScriptParserBase.java`](src/main/java/org/zaproxy/zap/extension/ascanrules/parserapi/impl/JavaScriptParserBase.java), with wildcard imports removed;
 - [`JavaScriptLexer.g4`](src/main/antlr/org/zaproxy/zap/extension/ascanrules/parserapi/impl/JavaScriptLexer.g4);
 - [`JavaScriptParser.g4`](src/main/antlr/org/zaproxy/zap/extension/ascanrules/parserapi/impl/JavaScriptParser.g4).

The parser is automatically generated when the code is compiled through the [`antlr` Gradle plugin](https://docs.gradle.org/current/userguide/antlr_plugin.html).
