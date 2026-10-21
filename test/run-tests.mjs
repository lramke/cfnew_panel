import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Windows 的 npm 脚本不会展开通配符，由脚本自行列出测试文件。
const directory = new URL('../src/test/', import.meta.url);
const files = readdirSync(directory)
  .filter(name => name.endsWith('.test.mjs'))
  .sort()
  .map(name => fileURLToPath(new URL(name, directory)));

if (!files.length) {
  console.error('没有找到测试文件');
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...files], {
  stdio: 'inherit',
  env: {
    ...process.env,
    CFNEW_TEST_CORE: process.env.CFNEW_TEST_CORE || fileURLToPath(new URL('./core-fixture.mjs', import.meta.url)),
  },
});
process.exit(result.status ?? 1);
