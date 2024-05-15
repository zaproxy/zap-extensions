# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) 
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased


## [0.11.0] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.

### Added
- Support for menu weights (Issue 8369)
### Fixed
- Fix grammatical error in help content.

## [0.10.0] - 2024-02-12
### Changed
- Skip parsing of empty SVGs.
- Maintenance changes.
- Setting "Query Parameters Handling" via automation framework should now be more forgiving as to the case of the values (enums).

### Fixed
- Ensure issues in one parser don't break the whole parsing process.
- Fix exception that happened with absolute dotted URLs in inlined content.

## [0.9.0] - 2024-01-26
### Added
- Video link in help for Automation Framework job.

### Changed
- The sitemap.xml parser will now accept and process a greater range of possible file content (Issue 8299).

## [0.8.0] - 2023-12-19
### Changed
- Handle multiple "Link" HTTP Response headers.
- Maintenance changes.

## [0.7.0] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.
- Maintenance changes.

## [0.6.0] - 2023-09-07
### Changed
- Maintenance changes.
- Depend on newer versions of Automation Framework and Common Library add-ons (Related to Issue 7961).
- Use Common Library add-on to obtain the Value Generator (Issue 8016).

## [0.5.0] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.

## [0.4.0] - 2023-05-03
### Fixed
- Set content-length even when body is empty, unless GET request.

## [0.3.0] - 2023-02-23
### Changed
- Maintenance changes.
- Default number of threads to 2 * processor count.

### Added
- Support for parsing .DS_Store files to find paths to try (Issue 30).

### Fixed
- Spurious error message on setting user in AF job.

## [0.2.0] - 2023-01-03
### Changed
- Maintenance changes.

### Fixed
- Prevent exception if no display (Issue 3978).

## [0.1.0] - 2022-10-27

### Functional Improvements Compared to Previous Core Release

The following table illustrates the changes versus the previous core release(s) (2.11/2.11.1).

| Before                                                                                                                                  | After                                                                                                                                                                                                               |
|-----------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Base - Proper handling                                                                                                                  | Base - Proper handling                                                                                                                                                                                              |
| A, Link, Area - ‘href’ attribute                                                                                                        | A, Link, Area - 'href' attribute                                                                                                                                                                                    |
| Frame, IFrame, Script, Img - ‘src’ attribute                                                                                            | Applet, Audio, Embed, Frame, IFrame, Input, Script, Img, Video - 'src' attribute                                                                                                                                    |
| Meta - ‘http-equiv’ for ’location’ and ‘refresh’                                                                                        | Meta - 'http-equiv' for 'location', 'refresh' and 'Content-Security-Policy', 'name' for 'msapplication-config'                                                                                                      |
|                                                                                                                                         | Applet - 'codebase', 'archive' attributes                                                                                                                                                                           |
|                                                                                                                                         | Img - 'longdesc', 'lowsrc', 'dynsrc', 'srcset' attributes                                                                                                                                                           |
|                                                                                                                                         | Isindex - 'action' attribute                                                                                                                                                                                        |
|                                                                                                                                         | Object - 'codebase', 'data' attributes                                                                                                                                                                              |
|                                                                                                                                         | Svg - 'href' and 'xlink:href' attributes of 'image' and 'script' elements                                                                                                                                           |
|                                                                                                                                         | Table - 'background' attribute                                                                                                                                                                                      |
|                                                                                                                                         | Video - 'poster' attribute                                                                                                                                                                                          |
| Form - proper handling of Forms with both GET and POST method. The fields values are generated validly, including HTML 5.0 input types. | Form - proper handling of Forms with both GET and POST method. The fields values are generated validly, including HTML 5.0 input types 'form', 'formaction', 'formmethod' attributes of buttons are also respected. |
| Comments - Valid tags found in comments are also analyzed, if specified in the Options Spider screen                                    | Comments - Valid tags found in comments are also analyzed, if specified in the Options Spider screen                                                                                                                |
|                                                                                                                                         | Import - 'implementation' attribute                                                                                                                                                                                 |
|                                                                                                                                         | Inline string - 'p', 'title', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', and 'blockquote' tags                                                                                                                       |
|                                                                                                                                         | SVG image files are parsed to identify HREF attributes and extract/resolve any contained links. (Issue 4984)                                                                                                        |
|                                                                                                                                         | Irrelevant Parameters - Allows to manage the parameters that should be removed when canonicalising the URLs found. The session token names defined in the HTTP Sessions options are taken into account and removed (Issue 4388). |

[0.11.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.11.0
[0.10.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.10.0
[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.9.0
[0.8.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.8.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.1.0
