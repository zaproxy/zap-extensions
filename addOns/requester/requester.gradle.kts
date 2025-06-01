import com.diffplug.spotless.extra.wtp.EclipseWtpFormatterStep
import org.zaproxy.gradle.addon.AddOnStatus

description = "Allows to manually edit and send messages."

zapAddOn {
    addOnName.set("Requester")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("Surikato and the ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/requester/")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">=1.23.0")
                }
            }
        }

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

crowdin {
    configuration {
        tokens.put("%messagesPath%", "org/zaproxy/addon/${zapAddOn.addOnId.get()}/")
        tokens.put("%helpPath%", "")
    }
}

spotless {
    format("help-html", {
        eclipseWtp(EclipseWtpFormatterStep.HTML)
        target(
            fileTree(projectDir) {
                include("src/**/help/**/*.html")
            },
        )
    })
}

dependencies {
    zapAddOn("commonlib")

    testImplementation(project(":testutils"))
}
