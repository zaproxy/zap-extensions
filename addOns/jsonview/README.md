Json view
=========
A simple Json indenter and beautifier.
Built after months of API testing on mobile applications that caused huge amounts of copy-pasting to jq.
Currently a very crude, yet helpful addon.

### ExtensionHttpPanelJsonView
The extension loader and handler, this is here mainly because nobody wants addons to touch the core code so it has to extend dynamically.
Contains some classes to manage the view enabling and selection too.

### HttpPanelJsonView
Controls the view, model, and Json data parsing.

### HttpPanelJsonArea
The syntax highlighted editable text area used for viewing and editing.

## Edge cases
application/json with empty body
	sometimes renders null into the sent body :(
application/json with huge data
	large request view not defaulted, causes loading delays in either
		identification/parsing
		rendering
	

