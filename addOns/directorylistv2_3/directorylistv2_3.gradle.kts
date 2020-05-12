import org.zaproxy.gradle.addon.AddOnStatus

version = "4"
description = "Lists of directory names to be used with Forced Browse or Fuzzer add-on."

zapAddOn {
    addOnName.set("Directory List v2.3")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/directory-list-v2.3/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}
