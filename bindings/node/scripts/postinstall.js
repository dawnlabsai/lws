#!/usr/bin/env node

/**
 * Post-install onboarding for @open-wallet-standard/core
 *
 * Runs after `npm install -g @open-wallet-standard/core` and walks the user
 * through optional first-time setup:
 *   1. Install the OWS skill for AI coding agents
 *   2. Create their first wallet
 *   3. Fund it with USDC via MoonPay
 *
 * Safety rules:
 *   - Only runs on global installs (skips `npm install` / `npm ci`)
 *   - Only runs in interactive terminals (silent in CI / piped stdin)
 *   - Only runs once per $HOME (persists marker at ~/.ows/.onboarding-done)
 *   - Entire main() is wrapped in .catch(() => {}) — never breaks installation
 *   - Zero external dependencies — Node.js built-ins only
 */

const { createInterface } = require("readline");
const { execFileSync, spawn } = require("child_process");
const { existsSync, mkdirSync, writeFileSync } = require("fs");
const { join } = require("path");

// ── ANSI helpers ────────────────────────────────────────────────────────────

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const RESET = "\x1b[0m";

const write = (msg) => process.stderr.write(msg);
const writeln = (msg = "") => process.stderr.write(msg + "\n");

// ── Helpers ─────────────────────────────────────────────────────────────────

function prompt(question) {
  return new Promise((resolve) => {
    let resolved = false;
    const done = (value) => {
      if (resolved) return;
      resolved = true;
      resolve(value);
    };
    const rl = createInterface({
      input: process.stdin,
      output: process.stderr,
    });
    rl.question(question, (answer) => {
      done(answer.trim());
      rl.close();
    });
    rl.on("close", () => done(""));
  });
}

function promptYesNo(question) {
  return prompt(`${question} ${DIM}[Y/n]${RESET} `).then(
    (a) => a === "" || /^y(es)?$/i.test(a)
  );
}

function run(cmd, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      stdio: "inherit",
      shell: process.platform === "win32",
    });
    child.on("close", (code) =>
      code === 0
        ? resolve()
        : reject(new Error(`${cmd} exited with code ${code}`))
    );
    child.on("error", reject);
  });
}

/**
 * Resolve the ows binary path. Checks in order:
 *   1. Platform-specific optional dependency (node_modules)
 *   2. Local npm/ directory (monorepo / dev builds)
 *   3. $PATH (already-installed global binary)
 */
function owsBinPath() {
  const PLATFORM_MAP = {
    "darwin-arm64": "@open-wallet-standard/core-darwin-arm64",
    "darwin-x64": "@open-wallet-standard/core-darwin-x64",
    "linux-x64": "@open-wallet-standard/core-linux-x64-gnu",
    "linux-arm64": "@open-wallet-standard/core-linux-arm64-gnu",
  };

  const key = `${process.platform}-${process.arch}`;
  const pkg = PLATFORM_MAP[key];

  if (pkg) {
    // 1. node_modules resolve
    try {
      const pkgDir = require.resolve(`${pkg}/package.json`);
      const p = join(pkgDir, "..", "ows");
      if (existsSync(p)) return p;
    } catch {}

    // 2. local npm/ directory (monorepo / dev)
    const local = join(__dirname, "..", "npm", pkg.split("/").pop(), "ows");
    if (existsSync(local)) return local;
  }

  // 3. Fall back to ows on $PATH (global install already linked)
  try {
    execFileSync("ows", ["--version"], {
      stdio: "ignore",
      shell: process.platform === "win32",
    });
    return "ows";
  } catch {}

  return null;
}

function hasNpx() {
  try {
    execFileSync("npx", ["--version"], {
      stdio: "ignore",
      shell: process.platform === "win32",
    });
    return true;
  } catch {
    return false;
  }
}

function skillInstalled() {
  const home = process.env.HOME || process.env.USERPROFILE || "";
  const dirs = [
    join(home, ".claude", "skills", "ows"),
    join(home, ".claude", "skills", "core"),
    join(home, ".claude", "skills", "open-wallet-standard--core"),
  ];
  return dirs.some((d) => existsSync(d));
}

function onboardingDone() {
  const home = process.env.HOME || process.env.USERPROFILE || "";
  return existsSync(join(home, ".ows", ".onboarding-done"));
}

function markOnboardingDone() {
  const home = process.env.HOME || process.env.USERPROFILE || "";
  const dir = join(home, ".ows");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, ".onboarding-done"), "", "utf8");
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  // Only run on global installs
  if (process.env.npm_config_global !== "true") return;

  // Only run in interactive terminals — stay silent in CI / piped stdin
  if (!process.stdin.isTTY) return;

  // Only run once — skip if the user already completed onboarding
  if (onboardingDone()) return;

  // Mark onboarding as shown so upgrades won't re-prompt
  markOnboardingDone();

  writeln();
  writeln(`${GREEN}${BOLD}✦ Open Wallet Standard CLI installed!${RESET}`);
  writeln(
    `${DIM}  Universal wallet for 10+ chains — one seed, all addresses.${RESET}`
  );
  writeln();

  // ── Step 1: Install the OWS skill for AI coding agents ──────────────────

  if (!skillInstalled() && hasNpx()) {
    const installSkill = await promptYesNo(
      `${CYAN}Install the OWS skill for your AI coding agent?${RESET}`
    );

    if (installSkill) {
      writeln();
      writeln(`${DIM}Installing skill...${RESET}`);
      try {
        await run("npx", [
          "-y",
          "skills",
          "add",
          "https://github.com/open-wallet-standard/core",
          "--skill",
          "ows",
        ]);
        writeln(`${GREEN}Skill installed.${RESET}`);
      } catch {
        writeln(
          `${YELLOW}Skill installation failed. You can install it later:${RESET}`
        );
        writeln(
          `  npx skills add https://github.com/open-wallet-standard/core --skill ows`
        );
      }
      writeln();
    } else {
      writeln(
        `${DIM}  Skipped. Install later: npx skills add https://github.com/open-wallet-standard/core --skill ows${RESET}`
      );
      writeln();
    }
  }

  // ── Step 2: Create first wallet ─────────────────────────────────────────

  const bin = owsBinPath();
  if (!bin) {
    writeln(
      `${DIM}Could not locate ows binary for this platform — skip wallet setup.${RESET}`
    );
    writeln(
      `${DIM}Run 'ows wallet create --name my-wallet' manually after install completes.${RESET}`
    );
    writeln();
    return;
  }

  const createWallet = await promptYesNo(
    `${CYAN}Create your first wallet?${RESET}`
  );

  if (!createWallet) {
    writeln(
      `${DIM}  Skipped. Create one anytime: ows wallet create --name my-wallet${RESET}`
    );
    writeln();
    return;
  }

  const walletName =
    (await prompt(`${CYAN}Wallet name ${DIM}[my-wallet]${RESET}: `)) ||
    "my-wallet";

  writeln();
  writeln(`${DIM}Creating wallet "${walletName}"...${RESET}`);

  try {
    await run(bin, ["wallet", "create", "--name", walletName]);
    writeln();
    writeln(`${GREEN}${BOLD}Wallet "${walletName}" created!${RESET}`);
  } catch {
    writeln(`${YELLOW}Wallet creation failed. Try manually:${RESET}`);
    writeln(`  ows wallet create --name ${walletName}`);
    writeln();
    return;
  }

  // ── Step 3: Fund the wallet ─────────────────────────────────────────────

  writeln();
  const fundWallet = await promptYesNo(
    `${CYAN}Fund your wallet with USDC via MoonPay?${RESET}`
  );

  if (!fundWallet) {
    writeln(
      `${DIM}  Skipped. Fund anytime: ows fund deposit --wallet ${walletName}${RESET}`
    );
    writeln();
    return;
  }

  writeln();
  writeln(
    `${DIM}Opening MoonPay deposit for "${walletName}" (Base USDC)...${RESET}`
  );

  try {
    await run(bin, [
      "fund",
      "deposit",
      "--wallet",
      walletName,
      "--chain",
      "base",
      "--token",
      "USDC",
    ]);
    writeln();
    writeln(`${GREEN}Deposit created! Follow the MoonPay instructions above.${RESET}`);
  } catch {
    writeln(`${YELLOW}Deposit failed. Try manually:${RESET}`);
    writeln(`  ows fund deposit --wallet ${walletName} --chain base --token USDC`);
  }

  writeln();
  writeln(`${BOLD}You're all set! Run ${CYAN}ows --help${RESET}${BOLD} to explore.${RESET}`);
  writeln();
}

main().catch(() => {});
