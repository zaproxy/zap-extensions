## Project Overview

This project contains official add-ons for ZAP, the Zed Attack Proxy.
ZAP is a tool for finding vulnerabilities in web applications.

## Project Structure

The main functionality is in the addOns directory.
Each add-on is contained in its own directory underneath addOns.

## Build and Test Instructions

To build an add-on called 'example' use `./gradlew :addOns:example:compileJava`

To run the unit tests use:  `./gradlew :addOns:example:test`

## Development Guidelines

- Always use modern Java features when relevant.
- Always i18n any strings which will appear in the UI.
- Do not duplicate code, instead create reusable methods.
- Prefer use of imports over fully qualified class names, unless there is a collision.
- Avoid unnecessary intermediate variables.
- For UI code put as much functionality as possible into non UI code to make it easier to add unit tests for it.
