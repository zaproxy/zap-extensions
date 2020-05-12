import org.zaproxy.gradle.addon.AddOnStatus

version = "5"
description = "List of directory names to be used with Forced Browse or Fuzzer add-on."

zapAddOn {
    addOnName.set("Directory List v1.0")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/directory-list-v1.0/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}
