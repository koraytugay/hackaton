import { readFileSync } from 'fs';
import * as path from 'path';
import {ComponentIdentifier} from './ComponentIdentifier';
import axios, {AxiosError, AxiosRequestConfig} from 'axios';
import * as core from '@actions/core';
import * as github from '@actions/github';

export interface Dependency {
  identifier: ComponentIdentifier;
  scope: string;
  children: Dependency[];
  isModule: boolean;
  isDirect: boolean | undefined; // if undefined, we do not know whether or not direct or transitive
}

async function run(): Promise<void> {
  try {
    let filePath = path.resolve(process.cwd(), 'source-dependency-tree.txt');
    const sourceDependencyTree = readFileSync(filePath, 'utf-8');

    core.info('✅ Successfully read source-dependency-tree.txt');
    core.info('📄 First few lines:');
    sourceDependencyTree.split('\n').slice(0, 20).forEach((line, index) => {
      core.info(`${index + 1}: ${line}`);
    });

    const sourceDependencies = parseDependencyTreeOutput(sourceDependencyTree) as Dependency[];

    filePath = path.resolve(process.cwd(), 'master', 'master-dependency-tree.txt');
    const masterDependencyTree = readFileSync(filePath, 'utf-8');

    core.info('✅ Successfully read master-dependency-tree.txt');
    core.info('📄 First few lines:');
    masterDependencyTree.split('\n').slice(0, 20).forEach((line, index) => {
      core.info(`${index + 1}: ${line}`);
    });

    const masterDependencies = parseDependencyTreeOutput(masterDependencyTree) as Dependency[];

    const diff = [];

    for (let i = 0; i < sourceDependencies.length; i++) {
      let existsInMaster = false;
      for (let j = 0; j < masterDependencies.length; j++) {
        if (sourceDependencies[i].identifier.getName() === masterDependencies[j].identifier.getName()) {
          if (sourceDependencies[i].identifier.getVersion() === masterDependencies[j].identifier.getVersion()) {
            existsInMaster = true;
          }
        }
      }
      if (!existsInMaster) {
        diff.push(sourceDependencies[i]);
      }
    }

    core.info('New components:');
    for (let i = 0; i < diff.length; i++) {
      core.info('New direct dependency:');
      core.info(`${diff[i].identifier.getName()} ${diff[i].identifier.getVersion()}`);
      if (diff[i].children) {
        core.info('Transitive dependencies:');
        for (let j = 0; j < diff[i].children.length; j++) {
          core.info(`\t${diff[i].children[j].identifier.getName()} ${diff[i].children[j].identifier.getVersion()}`);
        }
      }
    }

    let commentBody = '# Nexus IQ Found Policy Violations Introduced in this PR\n\n';

    for (let i = 0; i < diff.length; i++) {
      core.info('Sending request for direct dependency..');
      const directDependency = diff[i];
      core.info(`${directDependency.identifier.getName()} ${directDependency.identifier.getVersion()}`);
      let componentSummary = await getComponentSummary(directDependency.identifier);
      commentBody = commentBody + `'## Direct Dependency: ${directDependency.identifier.getName()} ${directDependency.identifier.getVersion()}\n`;
      if (componentSummary?.alerts) {
        for (const alert of componentSummary.alerts) {
          commentBody = commentBody + `#### ${alert.trigger.threatLevel} - ${alert.trigger.policyName}\n\n`;
          for (let componentFact of alert.trigger.componentFacts) {
            for (let constraintFact of componentFact.constraintFacts) {
              for (let conditionFact of constraintFact.conditionFacts) {
                commentBody = commentBody + `- ${constraintFact.constraintName} - ${conditionFact.reason}\n`
                // commentBody = commentBody + `- ${constraintFact.constraintName} - ${conditionFact.summary}\n`
              }
            }
          }
        }
      }

      core.info(JSON.stringify(componentSummary));
      if (directDependency.children) {
        core.info('Sending request for transitive dependency..');
        for (let j = 0; j < directDependency.children.length; j++) {
          let childDependency = directDependency.children[j];
          core.info(`\t${childDependency.identifier.getName()} ${childDependency.identifier.getVersion()}`);
          const transitiveSummary = await getComponentSummary(childDependency.identifier);
          componentSummary = await getComponentSummary(childDependency.identifier);
          // commentBody = commentBody + `${childDependency.identifier.getName()} ${childDependency.identifier.getVersion()}\n`;
          commentBody = commentBody + `'### Transitive Dependency: ${directDependency.identifier.getName()} ${directDependency.identifier.getVersion()}\n`;
          if (componentSummary?.alerts) {
            for (const alert of componentSummary.alerts) {
              commentBody = commentBody + `#### ${alert.trigger.threatLevel} - ${alert.trigger.policyName}\n\n`;
              for (let componentFact of alert.trigger.componentFacts) {
                for (let constraintFact of componentFact.constraintFacts) {
                  for (let conditionFact of constraintFact.conditionFacts) {
                    commentBody = commentBody + `- ${constraintFact.constraintName} - ${conditionFact.reason}\n`
                    // commentBody = commentBody + `- ${constraintFact.constraintName} - ${conditionFact.summary}\n`
                  }
                }
              }
            }
          }
          core.info(JSON.stringify(transitiveSummary));
        }
      }
    }

    await postComment(commentBody);

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

class ComponentSummary {
  alerts: PolicyAlert[];
  matchState: string;

  constructor(policyAlerts: PolicyAlert[], matchState: string) {
    this.alerts = policyAlerts;
    this.matchState = matchState;
  }
}

class PolicyAlert {
  trigger: Trigger;

  constructor(trigger: Trigger) {
    this.trigger = trigger;
  }
}

class Trigger {
  threatLevel: number;
  policyName: string;
  componentFacts: ComponentFact[];

  constructor(threatLevel: number, policyName: string, componentFacts: ComponentFact[]) {
    this.threatLevel = threatLevel;
    this.policyName = policyName;
    this.componentFacts = componentFacts;
  }
}

class ComponentFact {
  constraintName: string;
  constraintFacts: ConstraintFact[];

  constructor(constraintName: string, constraintFacts: ConstraintFact[]) {
    this.constraintName = constraintName;
    this.constraintFacts = constraintFacts;
  }
}

class ConstraintFact {
  constraintName: string;
  conditionFacts: ConditionFact[];

  constructor(constraintName: string, conditionFacts: ConditionFact[]) {
    this.constraintName = constraintName;
    this.conditionFacts = conditionFacts;
  }
}

class ConditionFact {
  summary: string;
  reason: string;

  constructor(summary: string, reason: string) {
    this.summary = summary;
    this.reason = reason;
  }
}


async function getComponentSummary(
    componentIdentifier: ComponentIdentifier,
): Promise<ComponentSummary | undefined> {
  const iqServerUrl = 'https://int-test.sonatype.app/platform'
  const username = process.env.USERNAME;
  const password = process.env.PASSWORD;


  if (!iqServerUrl || !username || !password) {
    core.info('IQ Server is not authenticated due to missing configuration.');
    return undefined;
  }

  const url = `${iqServerUrl}/rest/ide/scan/coordinates/kt-test?componentIdentifier=${componentIdentifier.toJson()}`;
  try {
    const config = await getAxiosConfig(url, username, password, 5000);
    const response = await axios.get(url, config);
    const componentSummary: ComponentSummary = response.data[0];
    return componentSummary;
  } catch (error) {
    if (error instanceof AxiosError) {
      core.info(`${error}`);
    }
    throw error;
  }
}

async function getAxiosConfig(
    url: string,
    username: string | undefined = undefined,
    password: string | undefined = undefined,
    timeout: number = 1000,
): Promise<AxiosRequestConfig> {
  const config: AxiosRequestConfig = {
  timeout,
};

if (username && password) {
  config.auth = { username, password };
}

return config;
}

async function postComment(commentBody: string) {
  try {
    const token = process.env.GITHUB_TOKEN;
    if (!token) throw new Error('GITHUB_TOKEN is not defined');

    const octokit = github.getOctokit(token);
    const context = github.context;

    // Ensure this is a pull request event
    const pullRequestNumber = context.payload.pull_request?.number;
    if (!pullRequestNumber) {
      core.info('Not a pull request – skipping comment.');
      return;
    }

    const owner = context.repo.owner;
    const repo = context.repo.repo;

    // const commentBody = `👋 Hello from your custom action! I just analyzed your PR and here’s something cool: 🎉`;

    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: pullRequestNumber,
      body: commentBody,
    });

    core.info('✅ Comment posted to PR');

  } catch (error) {
    core.setFailed((error as Error).message);
  }
}


run();
