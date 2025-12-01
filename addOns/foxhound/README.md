# Foxhound ZAP Plugin Development Notes

Detailed instructions can be found here: https://www.zaproxy.org/docs/developer/quick-start-build/

To build (all the plugins), use:
```bash
./gradlew.bat copyZapAddOn
```

For just Foxhound:
```bash
./gradlew.bat addOns:foxhound:copyZapAddOn
```

Then navigate to the zap folder and execute:

```bash
./gradlew.bat run
```
# Taint flow views

https://www.comp.nus.edu.sg/~cs3283/ftp/Java/swingConnect/tech_topics/tables-trees/tables-trees.html
https://www.comp.nus.edu.sg/~cs3283/ftp/Java/swingConnect/tech_topics/treemodel/treemodel.html

Taint View Panel with a TableTree, need a view to update it


## Development

Light-weight to do list targeting Black Hat in December 2025, in rough order of priority. Goal is an [alpha](https://github.com/zaproxy/zap-extensions/wiki/AddOnDevelopment) release.

- [x] Allow foxhound to be launched automatically via the ZAP browser menu (perhaps by specifying path for Firefox)
- [ ] Make the port of the Taint export server configurable
- [x] Add more details to the taint report
  - [x] Details about sources and sinks
  - [ ] Additional vulnerability types (stored client-side XSS, CSRF, etc...)
- [ ] Integrate messages into internationalization framework
- [x] Add taint viewer window to list all taint flows discovered
- [ ] Persist taint flows to a particular session
- [ ] Add exploit generation
- [ ] Add active scanning
- [ ] Website to showcase plugin
