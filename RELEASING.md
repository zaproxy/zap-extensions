# Release

The following steps should be followed to release the add-ons:
 1. Run the workflow [Prepare Release Add-on](https://github.com/zaproxy/zap-extensions/actions/workflows/prepare-release-add-on.yml)
    indicating, with a comma separated list, the IDs of the add-ons that should be released (e.g. `reveal, ascanrules`). It creates a
    pull request updating the versions and changelogs;
 2. Merge the pull request.

After merging the pull request the [Release Add-on](https://github.com/zaproxy/zap-extensions/actions/workflows/release-add-on.yml) workflow
will create the tag(s), create the release(s), trigger the update of the marketplace, and create a pull request preparing the next development iterations.
