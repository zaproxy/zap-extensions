## JavaScript Lexer

The JavaScript lexer used in this add-on is generated using ANTLR with their [JavaScript grammar](https://github.com/antlr/grammars-v4/tree/ff2f66fa8663e52a41b8ff2ad7d6237e4b3293d4/javascript/javascript).

The following files were copied from the referenced repository:
 - [`JavaScriptLexerBase.java`](src/main/java/org/zaproxy/zap/extension/pscanrules/antlr/JavaScriptLexerBase.java);
 - [`JavaScriptLexer.g4`](src/main/antlr/org/zaproxy/zap/extension/pscanrules/antlr/JavaScriptLexer.g4);

The lexer is automatically generated when the code is compiled through the [`antlr` Gradle plugin](https://docs.gradle.org/current/userguide/antlr_plugin.html).
