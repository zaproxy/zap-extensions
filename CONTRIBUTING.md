# Contributing to zap-extensions

## Changelog

The relevant changes done to each add-on are tracked in its own `CHANGELOG.md` file, when doing a
pull request consider updating it with the change done. The changes should be added to the
Unreleased section.

## Format/Style Java Code

The Java code is formatted according to Google Java Style (AOSP variant). The build automatically checks
that the code conforms to the style (using [Spotless], which delegates to [google-java-format]), it can
also be used to format the code (with the Gradle task `spotlessJavaApply`) if the IDE/editor in use
does not support it.


[Spotless]: https://github.com/diffplug/spotless
[google-java-format]: https://github.com/google/google-java-format
