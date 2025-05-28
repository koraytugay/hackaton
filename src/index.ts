import * as core from '@actions/core';
import { readFileSync } from 'fs';
import * as path from 'path';

function run(): void {
  try {
    const filePath = path.resolve(process.cwd(), 'dependency-tree.txt');
    const content = readFileSync(filePath, 'utf-8');

    core.info('✅ Successfully read dependency-tree.txt');
    core.info('📄 First few lines:');
    content.split('\n').slice(0, 20).forEach((line, index) => {
      core.info(`${index + 1}: ${line}`);
    });

  } catch (error) {
    core.setFailed(`❌ Failed to read dependency-tree.txt: ${(error as Error).message}`);
  }
}

run();
