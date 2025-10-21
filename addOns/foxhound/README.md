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


