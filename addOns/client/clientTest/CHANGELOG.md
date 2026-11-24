# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## 2026-11-25
### Added
- Never loading test app (`/client/never-loads/`) with pages which never finish loading: a document which hangs, a script which hangs, and (streamed) a trickling document, a never ending server-sent events stream and a script which is never finished. Every page links to a `canary.html` page which loads normally.
- Automation Framework plans which run the Client Spider, with Firefox and Chrome, on each of the never loading pages and check that it finishes in good time and finds the page which loads normally.

## 2026-11-20
### Added
- A slow loading page (`/client/slow-load/page`) which responds after a configurable delay.
- A launch check, which launches a browser with a given page load strategy and checks that the ZAP browser extension was configured.
- Automation Framework plans which check that the ZAP browser extension is configured on launch with Firefox, with the `none` and the `normal` page load strategies.
