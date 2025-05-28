import * as core from '@actions/core';
import { readFileSync } from 'fs';
import * as path from 'path';
import {ComponentIdentifier} from './ComponentIdentifier';

export interface Dependency {
  identifier: ComponentIdentifier;
  scope: string;
  children: Dependency[];
  isModule: boolean;
  isDirect: boolean | undefined; // if undefined, we do not know whether or not direct or transitive
}

function run(): void {
  try {
    const filePath = path.resolve(process.cwd(), 'dependency-tree.txt');
    const dependencyTreeOutput = readFileSync(filePath, 'utf-8');

    core.info('✅ Successfully read dependency-tree.txt');
    core.info('📄 First few lines:');
    dependencyTreeOutput.split('\n').slice(0, 20).forEach((line, index) => {
      core.info(`${index + 1}: ${line}`);
    });

    const dependencyArray = parseDependencyTreeOutput(dependencyTreeOutput);

  } catch (error) {
    core.setFailed(`❌ Failed to read dependency-tree.txt: ${(error as Error).message}`);
  }
}

function parseDependencyTreeOutput(dependencyTreeOutput: string): Dependency[] | Error {
  let dependencies = new Array<Dependency>();
  const dependencyTreeOutputLines = dependencyTreeOutput.split(/\r?\n/);

  // Process the raw response and collect all node relations for every module in an array of arrays
  // Each inner array represent one diagraph, i.e. one module graph
  // [
  //   [
  //     [INFO] "com.sonatype.insight.brain:insight-brain-client:jar:1.174.0-SNAPSHOT" -> "org.sonatype.aether:aether-util:jar:1.13.1:compile" ;
  //     [INFO] "com.sonatype.insight.brain:insight-brain-client:jar:1.174.0-SNAPSHOT" -> "com.sonatype.insight.brain:insight-brain-db:test-jar:tests:1.174.0-SNAPSHOT:test" ;
  //   ]
  //   [
  //     [INFO]  "com.sonatype.insight.brain:insight-rm-common:jar:1.174.0-SNAPSHOT" -> "com.sonatype.insight.brain:insight-brain-client:jar:1.174.0-SNAPSHOT:compile" ;
  //     [INFO]  "com.sonatype.insight.brain:insight-rm-common:jar:1.174.0-SNAPSHOT" -> "com.sonatype.insight.scan:insight-scanner-archive:jar:2.36.76-01:compile" ;
  //   ]
  // ]
  let inDiagraphSection = false;
  const allModules = [];
  let thisModule = [];
  for (const dependencyTreeOutputLine of dependencyTreeOutputLines) {
    // This indicates a diagraph start for a module
    if (dependencyTreeOutputLine.startsWith('[INFO] digraph')) {
      thisModule = [];
      inDiagraphSection = true;
      continue;
    }
    // This indicates an end of a diagraph for a module
    if (dependencyTreeOutputLine === '[INFO]  } ') {
      inDiagraphSection = false;
      allModules.push(thisModule);
      thisModule = [];
      continue;
    }
    if (inDiagraphSection) {
      thisModule.push(dependencyTreeOutputLine);
    }
  }

  // Every line represents 2 maven components and the relationship between them
  // This is where we process the rows and build the dependency tree
  const diagraphLineSplitter = /"([^"]+)" -> "([^"]+)"/;

  for (const module of allModules) {
    if (module.length === 0) {
      continue;
    }

    const parsedDependencies = new Map<string, Dependency | undefined>();
    for (const diagraphLine of module) {
      let mavenCoordinates;
      const matches = diagraphLineSplitter.exec(diagraphLine);

      // "left" -> "right"
      const left: string = matches![1];
      const right: string = matches![2];

      let leftDependency;
      if (parsedDependencies.get(left) !== undefined) {
        leftDependency = parsedDependencies.get(left);
      } else {
        mavenCoordinates = left.split(':');
        leftDependency = createDependencyFromMavenCoordinates(mavenCoordinates);
        parsedDependencies.set(left, leftDependency);

        // If we are seeing a left dependency for the first time, it is a root node
        if ('test' === (leftDependency as Dependency).scope) {
          dependencies.push(leftDependency);
        } else {
          dependencies.push(leftDependency);
        }
      }

      let rightDependency;
      if (parsedDependencies.get(right) !== undefined) {
        rightDependency = parsedDependencies.get(right);
      } else {
        mavenCoordinates = right.split(':');
        rightDependency = createDependencyFromMavenCoordinates(mavenCoordinates);
        parsedDependencies.set(right, rightDependency);
      }

      if ('test' === (rightDependency as Dependency).scope) {
        leftDependency!.children.push(rightDependency!);
      } else {
        leftDependency!.children.push(rightDependency!);
      }
    }
  }

  // We have a tree of Dependency objects but we need to do some post-processing

  // remove poms, nothing to analyze
  dependencies = dependencies.filter((value) => value.identifier.coordinates.get('extension') !== 'pom');

  // If there are multiple root dependencies, these are maven modules
  if (dependencies.length > 1) {
    // If a module is a dependency to another module, remove it from that module
    // Otherwise the tree shows duplicate information and grows too large
    dependencies.forEach((dependency) => {
      dependency.children = dependency.children.filter(
          (child) => !dependencies.some((dep) => child.identifier.equals(dep.identifier))
      );

      // Making a component 'module = true' changes its behaviour slightly
      // Also modules are neither direct nor transitive
      dependency.isDirect = undefined;
      dependency.isModule = true;
      // Treat their immediate children as direct
      dependency.children.forEach((child) => {
        child.isDirect = true;
      });
    });
  }

  // If there is only one root dependency, nicer to show the maven components without the
  // parent module and setting them all to direct
  if (dependencies.length === 1) {
    dependencies = dependencies[0].children.map((dep) => ({ ...dep, isDirect: true }));
  }

  return dependencies;
}

function createDependencyFromMavenCoordinates(mavenCoordinates: string[]): Dependency {
  core.info(`Creating maven dependency from coordinates: ${mavenCoordinates}`);

  let identifier;
  let scope = undefined;
  if (mavenCoordinates.length === 4) {
    identifier = ComponentIdentifier.createMavenIdentifier(
        mavenCoordinates[0],
        mavenCoordinates[1],
        mavenCoordinates[2],
        '', // classifier is optional and can be missing
        mavenCoordinates[3]
    );
  } else if (mavenCoordinates.length === 5) {
    identifier = ComponentIdentifier.createMavenIdentifier(
        mavenCoordinates[0],
        mavenCoordinates[1],
        mavenCoordinates[2],
        '', // classifier is optional and can be missing
        mavenCoordinates[3]
    );
    scope = mavenCoordinates[4];
  } else {
    identifier = ComponentIdentifier.createMavenIdentifier(
        mavenCoordinates[0],
        mavenCoordinates[1],
        mavenCoordinates[2],
        mavenCoordinates[3],
        mavenCoordinates[4]
    );
    scope = mavenCoordinates[5];
  }

  const dependency = {
    identifier: identifier,
    scope,
    children: new Array<Dependency>(),
    isModule: false,
    isDirect: false,
  } as Dependency;

  core.info(`Returning dependency: ${dependency.identifier.getName()}`);
  core.info(`Returning dependency: ${dependency.identifier.getVersion()}`);

  return dependency;
}


run();
