# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) 
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
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

[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/spider-v0.1.0
