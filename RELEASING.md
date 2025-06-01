# Release

The following steps should be followed to release the add-ons:
 1. Run the workflow [Prepare Release Add-on](https://github.com/zaproxy/zap-extensions/actions/workflows/prepare-release-add-on.yml)
    indicating, with a comma separated list, the IDs of the add-ons that should be released (e.g. `reveal, ascanrules`). It creates a
    pull request updating the versions and changelogs;
 2. Merge the pull request.

After merging the pull request the [Release Add-on](https://github.com/zaproxy/zap-extensions/actions/workflows/release-add-on.yml) workflow
will create the tag(s), create the release(s), trigger the update of the marketplace, and create a pull request preparing the next development iterations.

## Localized Resources

The resources that require localization (e.g. `Messages.properties`, help pages) are uploaded to the ZAP projects in
[Crowdin](https://crowdin.com/) when the add-ons are released, if required (for pre-translation) the resources can be uploaded manually at anytime
by running the workflow [Crowdin Upload Files](https://github.com/zaproxy/zap-extensions/actions/workflows/crowdin-upload-files.yml) indicating,
with a comma separated list, the IDs of the add-ons that should have the files uploaded (e.g. `reveal, ascanrules`).

The resulting localized resources are added/updated in the repository periodically (through a workflow in the
[zap-admin repository](https://github.com/zaproxy/zap-admin/)).
