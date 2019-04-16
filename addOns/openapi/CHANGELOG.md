# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

- Added Accept header for importing an OpenAPI definition from an URL, in the proper format.
- Correct import of v1.2 definitions (Issue 5262).
- Fix exception when reporting errors.

## 12 - 2018-05-18

- Ignore BOM when parsing and don't rely on default character encoding (Issue 4676).

## 11 - 2018-05-15

- Include exception message in warning dialog when a parse error occurs (Issue 4667).
- Open previously chosen directory when importing local file.

## 10 - 2018-01-17

- Fallback to host of request URI (Issue 4271).

## 9 - 2017-12-13

- Update Swagger/OpenAPI parser (Issue 3479).
- Fix exception with ref parameters.

## 8 - 2017-11-24

- Fix NPE in BodyGenerator.
- Fix NPEs when a parameter is null.

## 7 - 2017-09-28

- Correct validations when importing a file through the API.

## 6 - 2017-06-02

- Support optional host override.
- Detect and warn on potential loops.
- Allow add-on to be unloaded dynamically.
- Support user specified values when importing (Issue 3344).
- Support older swagger formats (Issue 3598).

## 5 - 2017-05-05

- Run synchronously and return any warnings when importing via API or cmdline.

## 4 - 2017-04-21

- Fallback to scheme of request URI (Issue 3433).

## 3 - 2017-04-20

- Added cmdline support.

## 2 - 2017-04-18

- Configure Swagger library logging.

## 1 - 2017-03-30

- First Version

