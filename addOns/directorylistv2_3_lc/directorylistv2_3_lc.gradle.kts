import org.zaproxy.gradle.addon.AddOnStatus

description = "Lists of lower case directory names to be used with Forced Browse or Fuzzer add-on."

zapAddOn {
    addOnName.set("Directory List v2.3 LC")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.12.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/directory-list-v2.3-lc/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

crowdin {
    configuration {
        file.set(file("$rootDir/gradle/crowdin-help-only.yml"))
        tokens.put("%helpPath%", "")
    }
}
