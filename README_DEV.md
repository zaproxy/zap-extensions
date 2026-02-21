# Development Notes (Local Add-on Install)

Some ZAP builds do not expose an “Install add-on from file” option in the UI. In that case, install locally-built add-ons by copying the `.zap` file(s) into ZAP’s home `plugin/` directory and restarting ZAP.

## Build the `llm` add-on

```sh
cd /Users/gerbot/Desktop/project/zap-extensions
./gradlew :addOns:llm:jarZapAddOn

# Example output:
# [Incubating] Problems report is available at: file:///Users/gerbot/Desktop/project/zap-extensions/build/reports/problems/problems-report.html
# Deprecated Gradle features were used in this build, making it incompatible with Gradle 9.0.
# BUILD SUCCESSFUL in 4s
```

The resulting add-on should be under:

```sh
addOns/llm/build/zapAddOn/bin/*.zap
```

## Build the `fuzz` add-on

```sh
cd /Users/gerbot/Desktop/project/zap-extensions
./gradlew :addOns:fuzz:jarZapAddOn
```

The resulting add-on should be under:

```sh
addOns/fuzz/build/zapAddOn/bin/*.zap
```

## Build both at once

```sh
cd /Users/gerbot/Desktop/project/zap-extensions
./gradlew :addOns:llm:jarZapAddOn :addOns:fuzz:jarZapAddOn
```

## Install into ZAP (copy to `$ZAP_HOME/plugin/`)

Set `ZAP_HOME` to your ZAP home directory, then copy the add-on:

```sh
# macOS (common):
export ZAP_HOME="$HOME/Library/Application Support/ZAP"

# Linux (common):
# export ZAP_HOME="$HOME/.ZAP"

# Sanity check (if this prints nothing, your ZAP_HOME is not set):
echo "$ZAP_HOME"

mkdir -p "$ZAP_HOME/plugin"
cp addOns/llm/build/zapAddOn/bin/*.zap "$ZAP_HOME/plugin/"
cp addOns/fuzz/build/zapAddOn/bin/*.zap "$ZAP_HOME/plugin/"
```

Restart ZAP to load the updated add-on.

## Run ZAP (examples)

```sh
# macOS:
open -a "ZAP"

# Or if you have a script-based install:
# /path/to/ZAP/zap.sh
```
