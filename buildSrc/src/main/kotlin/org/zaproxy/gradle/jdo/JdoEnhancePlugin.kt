package org.zaproxy.gradle.jdo

import org.gradle.api.Action
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.language.jvm.tasks.ProcessResources
import org.gradle.process.ExecOperations
import org.gradle.process.JavaExecSpec
import javax.inject.Inject

abstract class JdoEnhanceExtension {
    abstract val persistenceUnitName: Property<String>
    abstract val persistenceFile: RegularFileProperty
    abstract val jdoEnhance: ConfigurableFileCollection
}

abstract class JdoEnhancePlugin
    @Inject
    constructor(
        private val execOperations: ExecOperations,
    ) : Plugin<Project> {
        override fun apply(project: Project) {
            val extension = project.extensions.create("jdoEnhance", JdoEnhanceExtension::class.java)
            extension.persistenceFile.set(project.file("src/main/resources/META-INF/persistence.xml"))
            val jdoEnhanceConfiguration =
                project.configurations.create("jdoEnhance") {
                    isCanBeResolved = true
                    isCanBeConsumed = false
                }
            extension.jdoEnhance.from(jdoEnhanceConfiguration)

            project.tasks.named("compileJava", JavaCompile::class.java) {
                val compileJava = this

                dependsOn("processResources")

                inputs.file(extension.persistenceFile)
                inputs.files(extension.jdoEnhance)

                inputs.property(
                    "jdoEnhance.persistenceUnitName",
                    extension.persistenceUnitName,
                )

                doLast {
                    if (!extension.persistenceUnitName.isPresent) {
                        return@doLast
                    }

                    val classesDir = compileJava.destinationDirectory.asFile.get()
                    val resourcesDir =
                        project.tasks
                            .named("processResources", ProcessResources::class.java)
                            .get()
                            .destinationDir

                    execOperations.javaexec(
                        Action<JavaExecSpec> {
                            classpath(
                                extension.jdoEnhance,
                                compileJava.classpath,
                                classesDir,
                                resourcesDir,
                            )
                            mainClass.set(
                                "org.datanucleus.enhancer.DataNucleusEnhancer",
                            )
                            args(
                                "-q",
                                "-api",
                                "JDO",
                                "-pu",
                                extension.persistenceUnitName.get(),
                            )
                        },
                    )
                }
            }
        }
    }
