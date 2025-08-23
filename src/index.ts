import { readFileSync } from 'fs';
import * as path from 'path';
import { ComponentIdentifier } from './ComponentIdentifier';
import axios, { AxiosError, AxiosRequestConfig } from 'axios';
import * as core from '@actions/core';
import * as github from '@actions/github';

const COMMENT_MARKER = '<!-- nx-iq-report:do-not-edit -->';

export interface Dependency {
  identifier: ComponentIdentifier;
  scope: string;
  children: Dependency[];
  isModule: boolean;
  isDirect: boolean | undefined; // undefined => module roots
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

const keyOf = (d: Dependency) => `${d.identifier.getName()}@${d.identifier.getVersion()}`;
const nameOf = (d: Dependency) => d.identifier.getName();
const versionOf = (d: Dependency) => d.identifier.getVersion();

type SevInfo = { label: string; color: string };

function severityInfo(n: number): SevInfo {
  if (n >= 8) return { label: `${n}`,  color: 'bf001f' }; // severity.critical
  if (n >= 4) return { label: `${n}`,  color: 'fc6d07' }; // severity.severe (high)
  if (n >= 2) return { label: `${n}`,  color: 'feb628' }; // severity.moderate (medium)
  if (n >= 1) return { label: `${n}`,  color: '3942a8' }; // severity.low
  if (n === 0) return { label: `${n}`,  color: '15a2ff' }; // severity.none
  return { label: 'Unspecified', color: '000000' };        // severity.unspecified
}

function severityBadge(n: number): string {
  const { label, color } = severityInfo(n);
  const labelEnc = encodeURIComponent(label);
  // Shields.io badge with your exact color (no '#'); blank message segment keeps a compact pill
  return `![${label}](https://img.shields.io/badge/${labelEnc}-%20-${color}?style=flat)`;
}

function computeDiff(left: Dependency[], right: Dependency[]): Dependency[] {
  const rightSet = new Set(right.map(keyOf));
  return left.filter(d => !rightSet.has(keyOf(d)));
}

function detectUpgrades(master: Dependency[], source: Dependency[]): { name: string; from: Dependency; to: Dependency }[] {
  const masterByName = new Map<string, Dependency>();
  for (const m of master) {
    masterByName.set(nameOf(m), m);
  }
  const upgrades: { name: string; from: Dependency; to: Dependency }[] = [];
  for (const s of source) {
    const m = masterByName.get(nameOf(s));
    if (m && versionOf(m) !== versionOf(s)) {
      upgrades.push({ name: nameOf(s), from: m, to: s });
    }
  }
  return upgrades;
}

function startDetails(summary: string) {
  return `<details><summary>${summary}</summary>\n\n`;
}
function endDetails() {
  return '\n</details>\n';
}

function getNumberOfViolations(summary: ComponentSummary | undefined, lower: number, upper: number) {
  if (!summary) {
    return 0;
  }

  let count = 0;

  for (const alert of summary.alerts) {
    if (alert.trigger && alert.trigger.threatLevel) {
      if (alert.trigger.threatLevel >= lower && alert.trigger.threatLevel <= upper) {
        count++;
      }
    }
  }

  return count;
}

function renderAlertsTable(summary?: ComponentSummary) {
  const rows: string[] = [];

  if (summary?.alerts) {
    summary.alerts = [...summary.alerts].sort(
        (a, b) => b.trigger.threatLevel - a.trigger.threatLevel
    );

    for (const alert of summary.alerts) {
      const sev = severityBadge(alert.trigger.threatLevel);
      for (const cf of alert.trigger.componentFacts) {
        for (const k of cf.constraintFacts) {
          const reasons = k.conditionFacts.map(cond => `- ${cond.reason}`).join('<br>');
          rows.push(`|${sev}|${alert.trigger.policyName}|${k.constraintName}|${reasons}|`);
        }
      }
    }
  }

  const deduped = Array.from(new Set(rows));

  if (deduped.length === 0) {
    return 'This component does not have any vulnerabilities.';
    // alternatively: 'No policy violations detected for this component.'
  }

  let out = '';
  out += '|Severity|Policy|Constraint|Reason|\n';
  out += '|--|--|--|--|\n';
  out += deduped.join('\n');
  return out;
}

// ===== UI Helpers (NEW; UI-only) =====
const BRAND = {
  green: '2ea043',   // GitHub success
  purple: '8957e5',  // GitHub purple
  gray: '6e7781',    // GitHub muted
};

const SEV = {
  critical: 'bf001f',
  high: 'fc6d07',
  medium: 'feb628',
};

function shield(label: string, value: string | number, color: string, style: 'flat' | 'for-the-badge' = 'flat') {
  const l = encodeURIComponent(label);
  const v = encodeURIComponent(String(value));
  return `<img alt="${label}: ${value}" src="https://img.shields.io/badge/${l}-${v}-${color}?style=${style}">`;
}

function statRow(introduced: number, upgraded: number, removed: number) {
  const parts = [
    shield('New', introduced, BRAND.green),
    '&nbsp;',
    shield('Upgraded', upgraded, BRAND.purple),
    '&nbsp;',
    shield('Removed', removed, BRAND.gray),
  ];
  return parts.join('');
}

/** Compact C/H/M pill trio (Critical / High / Medium) */
function triPills(c: number, h: number, m: number, title = '') {
  const t = title ? ` title="${title}"` : '';
  return `<span${t}>` +
      shield('C', c, SEV.critical) + '&nbsp;' +
      shield('H', h, SEV.high) + '&nbsp;' +
      shield('M', m, SEV.medium) +
      `</span>`;
}

/** Component line for <summary>: shows direct and (optional) transitive totals */
function componentSummaryLine(
    name: string,
    version: string,
    direct: { c: number; h: number; m: number },
    trans?: { c: number; h: number; m: number }
) {
  let s = `<strong>${name} ${version}</strong> &nbsp;•&nbsp; ${triPills(direct.c, direct.h, direct.m, 'Direct findings')}`;
  if (trans && (trans.c || trans.h || trans.m)) {
    s += ` &nbsp;—&nbsp; ${triPills(trans.c, trans.h, trans.m, 'Transitive findings')}`;
  }
  return s;
}

function sectionHeading(emoji: string, text: string) {
  return `\n\n### ${emoji} ${text}\n`;
}

function legendDetails() {
  return `<details><summary>Legend & Colors</summary>

**Severity:** ${shield('C', 'Critical', SEV.critical)} ${shield('H', 'High', SEV.high)} ${shield('M', 'Medium', SEV.medium)}  
**Badges:** numbers show count of policy violations at that severity.

</details>\n`;
}

// ===== Main =====
async function run(): Promise<void> {
  try {
    // --- Read dependency trees ---
    let filePath = path.resolve(process.cwd(), 'source-dependency-tree.txt');
    const sourceDependencyTree = readFileSync(filePath, 'utf-8');
    core.info('Successfully read source-dependency-tree.txt');
    sourceDependencyTree.split('\n').slice(0, 20).forEach((line, index) => core.info(`${index + 1}: ${line}`));
    const sourceDependencies = parseDependencyTreeOutput(sourceDependencyTree) as Dependency[];

    filePath = path.resolve(process.cwd(), 'master', 'master-dependency-tree.txt');
    const masterDependencyTree = readFileSync(filePath, 'utf-8');
    core.info('Successfully read master-dependency-tree.txt');
    masterDependencyTree.split('\n').slice(0, 20).forEach((line, index) => core.info(`${index + 1}: ${line}`));
    const masterDependencies = parseDependencyTreeOutput(masterDependencyTree) as Dependency[];

    // --- Compute diffs ---
    const upgrades = detectUpgrades(masterDependencies, sourceDependencies);
    const introducedRaw = computeDiff(sourceDependencies, masterDependencies);
    const removedRaw = computeDiff(masterDependencies, sourceDependencies);

    // Filter out upgrade pairs from introduced/removed so we only show them under "Upgrades"
    const introduced = introducedRaw.filter(d => !upgrades.some(u => keyOf(u.to) === keyOf(d)));
    const removed = removedRaw.filter(d => !upgrades.some(u => keyOf(u.from) === keyOf(d)));

    if (introduced.length === 0 && removed.length === 0 && upgrades.length === 0) {
      await postComment('No dependency changes detected.');
      return;
    }

    // --- Log for debugging ---
    if (introduced.length) {
      core.info('New components introduced:');
      introduced.forEach(d => {
        core.info(`${nameOf(d)} ${versionOf(d)}`);
        if (d.children?.length) {
          core.info('Transitives:');
          d.children.forEach(c => core.info(`\t${nameOf(c)} ${versionOf(c)}`));
        }
      });
    }
    if (removed.length) {
      core.info('Components removed (potentially solved violations):');
      removed.forEach(d => {
        core.info(`${nameOf(d)} ${versionOf(d)}`);
        if (d.children?.length) {
          core.info('Transitives:');
          d.children.forEach(c => core.info(`\t${nameOf(c)} ${versionOf(c)}`));
        }
      });
    }
    if (upgrades.length) {
      core.info('Detected upgrades:');
      upgrades.forEach(u => core.info(`${u.name}: ${versionOf(u.from)} -> ${versionOf(u.to)}`));
    }

    // --- Build comment (UI refreshed) ---
    const introducedCount = introduced.length;
    const removedCount = removed.length;
    const upgradeCount = upgrades.length;

    let commentBody = `# 🧪 Nexus IQ • PR Risk Dashboard\n\n`;
    commentBody += `> Snapshot of dependency policy risk introduced by this PR.\n\n`;
    commentBody += statRow(introducedCount, upgradeCount, removedCount) + '\n';
    commentBody += legendDetails();

    // === New Components ===
    if (introduced.length) {
      commentBody += sectionHeading('🧩', 'New Components');

      for (const dep of introduced) {
        const directSummary = await getComponentSummary(dep.identifier);

        const direct = {
          c: getNumberOfViolations(directSummary, 8, 10),
          h: getNumberOfViolations(directSummary, 4, 7),
          m: getNumberOfViolations(directSummary, 2, 3),
        };

        let trans = { c: 0, h: 0, m: 0 };

        if (dep.children?.length) {
          for (const child of dep.children) {
            const childSummary = await getComponentSummary(child.identifier);
            if (!childSummary?.alerts?.length) continue;
            trans.c += getNumberOfViolations(childSummary, 8, 10);
            trans.h += getNumberOfViolations(childSummary, 4, 7);
            trans.m += getNumberOfViolations(childSummary, 2, 3);
          }
        }

        const header = componentSummaryLine(nameOf(dep), versionOf(dep), direct, trans);
        commentBody += startDetails(header);

        // Direct findings
        commentBody += renderAlertsTable(directSummary);

        // Transitives with alerts
        if (dep.children?.length) {
          for (const child of dep.children) {
            const childSummary = await getComponentSummary(child.identifier);
            if (!childSummary?.alerts?.length) continue; // skip quiet transitives
            commentBody += `\n\n**Transitive:** \`${nameOf(child)} ${versionOf(child)}\`\n\n`;
            commentBody += renderAlertsTable(childSummary);
          }
        }

        commentBody += endDetails();
      }
      commentBody += '\n';
    }

    // === Version Changes ===
    if (upgrades.length) {
      commentBody += sectionHeading('⬆️', 'Version Changes');

      for (const u of upgrades) {
        const name = u.name;
        const before = versionOf(u.from);
        const after = versionOf(u.to);

        const beforeSummary = await getComponentSummary(u.from.identifier);
        const afterSummary  = await getComponentSummary(u.to.identifier);

        const beforeDirect = {
          c: getNumberOfViolations(beforeSummary, 8, 10),
          h: getNumberOfViolations(beforeSummary, 4, 7),
          m: getNumberOfViolations(beforeSummary, 2, 3),
        };

        const afterDirect = {
          c: getNumberOfViolations(afterSummary, 8, 10),
          h: getNumberOfViolations(afterSummary, 4, 7),
          m: getNumberOfViolations(afterSummary, 2, 3),
        };

        let beforeTrans = { c: 0, h: 0, m: 0 };
        if (u.from.children?.length) {
          for (const child of u.from.children) {
            const cs = await getComponentSummary(child.identifier);
            if (!cs?.alerts?.length) continue;
            beforeTrans.c += getNumberOfViolations(cs, 8, 10);
            beforeTrans.h += getNumberOfViolations(cs, 4, 7);
            beforeTrans.m += getNumberOfViolations(cs, 2, 3);
          }
        }

        let afterTrans = { c: 0, h: 0, m: 0 };
        if (u.to.children?.length) {
          for (const child of u.to.children) {
            const cs = await getComponentSummary(child.identifier);
            if (!cs?.alerts?.length) continue;
            afterTrans.c += getNumberOfViolations(cs, 8, 10);
            afterTrans.h += getNumberOfViolations(cs, 4, 7);
            afterTrans.m += getNumberOfViolations(cs, 2, 3);
          }
        }

        const header =
            `<strong>${name}</strong> &nbsp;` +
            `\`${before}\` ${triPills(beforeDirect.c, beforeDirect.h, beforeDirect.m, 'Before (direct)')}` +
            (beforeTrans.c || beforeTrans.h || beforeTrans.m
                ? ` &nbsp;—&nbsp; ${triPills(beforeTrans.c, beforeTrans.h, beforeTrans.m, 'Before (transitive)')}`
                : '') +
            ` &nbsp;→&nbsp; ` +
            `\`${after}\` ${triPills(afterDirect.c, afterDirect.h, afterDirect.m, 'After (direct)')}` +
            (afterTrans.c || afterTrans.h || afterTrans.m
                ? ` &nbsp;—&nbsp; ${triPills(afterTrans.c, afterTrans.h, afterTrans.m, 'After (transitive)')}`
                : '');

        commentBody += startDetails(header);

        commentBody += `**Before \`${before}\`**\n\n`;
        commentBody += renderAlertsTable(beforeSummary);

        commentBody += `\n\n**After \`${after}\`**\n\n`;
        commentBody += renderAlertsTable(afterSummary);

        commentBody += endDetails();
      }
      commentBody += '\n';
    }

    // === Removed Components ===
    if (removed.length) {
      commentBody += sectionHeading('➖', 'Removed Components');

      for (const dep of removed) {
        const directSummary = await getComponentSummary(dep.identifier);

        const direct = {
          c: getNumberOfViolations(directSummary, 8, 10),
          h: getNumberOfViolations(directSummary, 4, 7),
          m: getNumberOfViolations(directSummary, 2, 3),
        };

        let trans = { c: 0, h: 0, m: 0 };

        if (dep.children?.length) {
          for (const child of dep.children) {
            const childSummary = await getComponentSummary(child.identifier);
            if (!childSummary?.alerts?.length) continue;
            trans.c += getNumberOfViolations(childSummary, 8, 10);
            trans.h += getNumberOfViolations(childSummary, 4, 7);
            trans.m += getNumberOfViolations(childSummary, 2, 3);
          }
        }

        const header = componentSummaryLine(nameOf(dep), versionOf(dep), direct, trans);
        commentBody += startDetails(header);

        // Direct table
        commentBody += renderAlertsTable(directSummary);

        // Per-transitive details (only if any alerts)
        if (dep.children?.length) {
          for (const child of dep.children) {
            const childSummary = await getComponentSummary(child.identifier);
            if (!childSummary?.alerts?.length) continue;
            commentBody += `\n\n**Transitive Removed:** \`${nameOf(child)} ${versionOf(child)}\`\n\n`;
            commentBody += renderAlertsTable(childSummary);
          }
        }

        commentBody += endDetails();
      }
    }

    await postComment(commentBody);
  } catch (error) {
    core.setFailed(`Failed: ${(error as Error).message}`);
  }
}

// ===== Dependency Tree Parsing (unchanged core logic, just tidied) =====
function parseDependencyTreeOutput(dependencyTreeOutput: string): Dependency[] | Error {
  let dependencies = new Array<Dependency>();
  const dependencyTreeOutputLines = dependencyTreeOutput.split(/\r?\n/);

  let inDiagraphSection = false;
  const allModules: string[][] = [];
  let thisModule: string[] = [];

  for (const dependencyTreeOutputLine of dependencyTreeOutputLines) {
    if (dependencyTreeOutputLine.startsWith('[INFO] digraph')) {
      thisModule = [];
      inDiagraphSection = true;
      continue;
    }
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

  const diagraphLineSplitter = /"([^"]+)" -> "([^"]+)"/;

  for (const module of allModules) {
    if (module.length === 0) continue;

    const parsedDependencies = new Map<string, Dependency | undefined>();
    for (const diagraphLine of module) {
      const matches = diagraphLineSplitter.exec(diagraphLine);
      if (!matches) continue;

      // "left" -> "right"
      const left: string = matches[1];
      const right: string = matches[2];

      let leftDependency: Dependency | undefined = parsedDependencies.get(left);
      if (!leftDependency) {
        const mavenCoordinates = left.split(':');
        leftDependency = createDependencyFromMavenCoordinates(mavenCoordinates);
        parsedDependencies.set(left, leftDependency);
        dependencies.push(leftDependency);
      }

      let rightDependency: Dependency | undefined = parsedDependencies.get(right);
      if (!rightDependency) {
        const mavenCoordinates = right.split(':');
        rightDependency = createDependencyFromMavenCoordinates(mavenCoordinates);
        parsedDependencies.set(right, rightDependency);
      }

      leftDependency.children.push(rightDependency);
    }
  }

  // Remove poms
  dependencies = dependencies.filter((value) => value.identifier.coordinates.get('extension') !== 'pom');

  // If multiple root dependencies => modules
  if (dependencies.length > 1) {
    dependencies.forEach((dependency) => {
      dependency.children = dependency.children.filter(
          (child) => !dependencies.some((dep) => child.identifier.equals(dep.identifier))
      );
      dependency.isDirect = undefined;
      dependency.isModule = true;
      dependency.children.forEach((child) => {
        child.isDirect = true;
      });
    });
  }

  // Single root => show its children as direct
  if (dependencies.length === 1) {
    dependencies = dependencies[0].children.map((dep) => ({ ...dep, isDirect: true }));
  }

  return dependencies;
}

function createDependencyFromMavenCoordinates(mavenCoordinates: string[]): Dependency {
  core.info(`Creating maven dependency from coordinates: ${mavenCoordinates}`);

  let identifier: ComponentIdentifier;
  let scope: string | undefined = undefined;

  if (mavenCoordinates.length === 4) {
    identifier = ComponentIdentifier.createMavenIdentifier(
        mavenCoordinates[0],
        mavenCoordinates[1],
        mavenCoordinates[2],
        '',
        mavenCoordinates[3]
    );
  } else if (mavenCoordinates.length === 5) {
    identifier = ComponentIdentifier.createMavenIdentifier(
        mavenCoordinates[0],
        mavenCoordinates[1],
        mavenCoordinates[2],
        '',
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
    identifier,
    scope,
    children: new Array<Dependency>(),
    isModule: false,
    isDirect: false,
  } as Dependency;

  core.info(`Returning dependency: ${dependency.identifier.getName()}`);
  core.info(`Returning dependency: ${dependency.identifier.getVersion()}`);

  return dependency;
}

// ===== IQ API =====
async function getComponentSummary(
    componentIdentifier: ComponentIdentifier,
): Promise<ComponentSummary | undefined> {
  const iqServerUrl = 'https://int-test.sonatype.app/platform';
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
    _url: string,
    username: string | undefined = undefined,
    password: string | undefined = undefined,
    timeout: number = 1000,
): Promise<AxiosRequestConfig> {
  const config: AxiosRequestConfig = { timeout };
  if (username && password) {
    config.auth = { username, password };
  }
  return config;
}

// ===== GitHub comment =====
async function postComment(commentBody: string, opts: { mode?: 'update' | 'replace' } = {}) {
  const { mode = 'update' } = opts;

  try {
    const token = process.env.GITHUB_TOKEN;
    if (!token) throw new Error('GITHUB_TOKEN is not defined');

    const octokit = github.getOctokit(token);
    const context = github.context;

    const pullRequestNumber = context.payload.pull_request?.number;
    if (!pullRequestNumber) {
      core.info('Not a pull request – skipping comment.');
      return;
    }

    const { owner, repo } = context.repo;
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
        owner, repo, comment_id: previous.id, body,
      });
      core.info(`Updated existing comment (${previous.id})`);
      return;
    }

    if (previous && mode === 'replace') {
      await octokit.rest.issues.deleteComment({ owner, repo, comment_id: previous.id });
      core.info(`Deleted previous comment (${previous.id})`);
    }

    await octokit.rest.issues.createComment({ owner, repo, issue_number: pullRequestNumber, body });
    core.info('Created comment on PR');
  } catch (error) {
    core.setFailed((error as Error).message);
  }
}

run();
