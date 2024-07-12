import com.github.gradle.node.npm.task.NpmTask
import org.gradle.configurationcache.extensions.capitalized

description = "A Proof of Concept add-on for potential ZAP web based UIs."

plugins {
    id("com.github.node-gradle.node") version "7.0.2"
}

node {
    version = "20.13.0"
    download = true
}

val pocsSrcDir = projectDir.resolve("src/main/pocs")
val pocsBuildDir = layout.buildDirectory.dir("pocs").get()
val pocBuildTasks: MutableList<TaskProvider<*>> = mutableListOf()
val pocBuildTasksGroup = "ZAP Web UI PoC Build"
for (dir in pocsSrcDir.listFiles()!!) {
    val packageJson = File(dir, "package.json")
    val outputDir = pocsBuildDir.dir("webuipoc").dir(dir.name)
    val normalizedPocName = dir.name.capitalized()
    if (packageJson.exists()) {
        val installTask =
            tasks.register<NpmTask>("installPoc${normalizedPocName}Dependencies") {
                group = pocBuildTasksGroup
                workingDir = dir
                args.set(arrayListOf("install"))
            }
        pocBuildTasks.add(
            tasks.register<NpmTask>("assemblePoc$normalizedPocName") {
                group = pocBuildTasksGroup
                dependsOn(installTask)
                workingDir = dir
                args.set(arrayListOf("run", "build"))
                doLast {
                    copy {
                        from(File(dir, "dist"))
                        into(outputDir)
                    }
                }
            },
        )
    } else {
        pocBuildTasks.add(
            tasks.register("assemblePoc$normalizedPocName") {
                group = pocBuildTasksGroup
                doLast {
                    copy {
                        from(dir)
                        into(outputDir)
                    }
                }
            },
        )
    }
}
sourceSets["main"].output.dir(mapOf("builtBy" to pocBuildTasks), pocsBuildDir)

zapAddOn {
    addOnName.set("Web UI PoC")

    manifest {
        author.set("ZAP Dev Team")

        dependencies {
            addOns {
                register("network") {
                    version.set(">=0.13.0")
                }
            }
        }

        files.from(pocsBuildDir)
    }
}

dependencies {
    zapAddOn("network")
}
