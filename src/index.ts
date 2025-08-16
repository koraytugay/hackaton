import { readFileSync } from 'fs';
import * as path from 'path';
import {ComponentIdentifier} from './ComponentIdentifier';
import axios, {AxiosError, AxiosRequestConfig} from 'axios';
import * as core from '@actions/core';
import * as github from '@actions/github';

const COMMENT_MARKER = '<!-- nx-iq-report:do-not-edit -->';

export interface Dependency {
  identifier: ComponentIdentifier;
  scope: string;
  children: Dependency[];
  isModule: boolean;
  isDirect: boolean | undefined; // if undefined, we do not know whether or not direct or transitive
}

// ADD near the top, after interfaces
const keyOf = (d: Dependency) => `${d.identifier.getName()}@${d.identifier.getVersion()}`;

function computeDiff(left: Dependency[], right: Dependency[]): Dependency[] {
  const rightSet = new Set(right.map(keyOf));
  return left.filter(d => !rightSet.has(keyOf(d)));
}

function renderAlertsTable(componentSummary?: ComponentSummary): string {
  let out = '';
  out += '|Threat Level|Policy|Constraint|Reason|\n';
  out += '|--|--|--|--|\n';

  if (componentSummary?.alerts) {
    for (const alert of componentSummary.alerts) {
      for (const componentFact of alert.trigger.componentFacts) {
        for (const constraintFact of componentFact.constraintFacts) {
          for (const conditionFact of constraintFact.conditionFacts) {
            out += `|${alert.trigger.threatLevel}|${alert.trigger.policyName}|${constraintFact.constraintName}|${conditionFact.reason}|\n`;
          }
        }
      }
    }
  }
  return out;
}

async function run(): Promise<void> {
  try {
    let filePath = path.resolve(process.cwd(), 'source-dependency-tree.txt');
    const sourceDependencyTree = readFileSync(filePath, 'utf-8');

    core.info('Successfully read source-dependency-tree.txt');
    core.info('First few lines:');
    sourceDependencyTree.split('\n').slice(0, 20).forEach((line, index) => {
      core.info(`${index + 1}: ${line}`);
    });

    const sourceDependencies = parseDependencyTreeOutput(sourceDependencyTree) as Dependency[];

    filePath = path.resolve(process.cwd(), 'master', 'master-dependency-tree.txt');
    const masterDependencyTree = readFileSync(filePath, 'utf-8');

    core.info('Successfully read master-dependency-tree.txt');
    core.info('First few lines:');
    masterDependencyTree.split('\n').slice(0, 20).forEach((line, index) => {
      core.info(`${index + 1}: ${line}`);
    });

    const masterDependencies = parseDependencyTreeOutput(masterDependencyTree) as Dependency[];

    const introduced = computeDiff(sourceDependencies, masterDependencies);
    const removed = computeDiff(masterDependencies, sourceDependencies);

// Early exit if nothing changed at all
    if (introduced.length === 0 && removed.length === 0) {
      await postComment('No new components introduced and no previous components removed.');
      return;
    }

// Log for visibility
    if (introduced.length) {
      core.info('New components introduced:');
      introduced.forEach(d => {
        core.info(`${d.identifier.getName()} ${d.identifier.getVersion()}`);
        if (d.children?.length) {
          core.info('Transitives:');
          d.children.forEach(c =>
              core.info(`\t${c.identifier.getName()} ${c.identifier.getVersion()}`),
          );
        }
      });
    }

    if (removed.length) {
      core.info('Components removed (potentially solved violations):');
      removed.forEach(d => {
        core.info(`${d.identifier.getName()} ${d.identifier.getVersion()}`);
        if (d.children?.length) {
          core.info('Transitives:');
          d.children.forEach(c =>
              core.info(`\t${c.identifier.getName()} ${c.identifier.getVersion()}`),
          );
        }
      });
    }

    let commentBody = '';

    /** Introduced section (existing behavior, refactored a bit) */
    if (introduced.length) {
      commentBody += '# Nexus IQ Found Policy Violations Introduced in this PR\n\n';

      for (const directDependency of introduced) {
        core.info('Sending request for direct dependency (introduced)..');
        core.info(`${directDependency.identifier.getName()} ${directDependency.identifier.getVersion()}`);

        const directSummary = await getComponentSummary(directDependency.identifier);
        commentBody += `## Direct Dependency: ${directDependency.identifier.getName()} ${directDependency.identifier.getVersion()}\n`;
        commentBody += renderAlertsTable(directSummary);

        if (directDependency.children?.length) {
          core.info('Sending request for transitive dependencies (introduced)..');
          for (const child of directDependency.children) {
            core.info(`\t${child.identifier.getName()} ${child.identifier.getVersion()}`);
            const transitiveSummary = await getComponentSummary(child.identifier);
            commentBody += `### Transitive Dependency: ${child.identifier.getName()} ${child.identifier.getVersion()}\n`;
            commentBody += renderAlertsTable(transitiveSummary);
          }
        }
      }
    }

    /** Solved section (NEW) */
    if (removed.length) {
      commentBody += '\n# Nexus IQ Found Determined Violations Solved in this PR\n\n';

      for (const directDependency of removed) {
        core.info('Sending request for direct dependency (removed/solved)..');
        core.info(`${directDependency.identifier.getName()} ${directDependency.identifier.getVersion()}`);

        const directSummary = await getComponentSummary(directDependency.identifier);
        commentBody += `## Direct Dependency Removed: ${directDependency.identifier.getName()} ${directDependency.identifier.getVersion()}\n`;
        commentBody += renderAlertsTable(directSummary);

        if (directDependency.children?.length) {
          core.info('Sending request for transitive dependencies (removed/solved)..');
          for (const child of directDependency.children) {
            core.info(`\t${child.identifier.getName()} ${child.identifier.getVersion()}`);
            const transitiveSummary = await getComponentSummary(child.identifier);
            commentBody += `### Transitive Dependency Removed: ${child.identifier.getName()} ${child.identifier.getVersion()}\n`;
            commentBody += renderAlertsTable(transitiveSummary);
          }
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

async function postComment(commentBody: string, opts: { mode?: 'update' | 'replace' } = {}) {
  const { mode = 'update' } = opts;

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

    const { owner, repo } = context.repo;

    // Always include the hidden marker so we can find our own comment reliably
    const body = `${COMMENT_MARKER}\n${commentBody}`;

    const comments = await octokit.paginate(octokit.rest.issues.listComments, {
      owner,
      repo,
      issue_number: pullRequestNumber,
      per_page: 100,
    });

    const previous = comments.find((c) => (c.body ?? '').includes(COMMENT_MARKER));

    if (previous && mode === 'update') {
      await octokit.rest.issues.updateComment({
        owner,
        repo,
        comment_id: previous.id,
        body,
      });
      core.info(`✅ Updated existing comment (${previous.id})`);
      return;
    }

    if (previous && mode === 'replace') {
      await octokit.rest.issues.deleteComment({
        owner,
        repo,
        comment_id: previous.id,
      });
      core.info(`🗑️ Deleted previous comment (${previous.id})`);
    }

    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: pullRequestNumber,
      body,
    });
    core.info('✅ Created comment on PR');
  } catch (error) {
    core.setFailed((error as Error).message);
  }
}


run();
