#!/usr/bin/env node

/**
 * Release script for SafeDrive.
 *
 * Bumps the app version in every manifest file, commits the change,
 * creates a git tag, and pushes — which triggers the GitHub Actions
 * release workflow.
 *
 * Usage:
 *   npm run release -- patch    # 0.1.0 → 0.1.1
 *   npm run release -- minor    # 0.1.0 → 0.2.0
 *   npm run release -- major    # 0.1.0 → 1.0.0
 *   npm run release -- 2.0.0    # explicit version
 */

import { readFileSync, writeFileSync } from "node:fs"
import { execSync } from "node:child_process"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..")

// ── Helpers ──────────────────────────────────────────────────────────

function run(cmd) {
  console.log(`  $ ${cmd}`)
  execSync(cmd, { cwd: ROOT, stdio: "inherit" })
}

function readJson(relPath) {
  return JSON.parse(readFileSync(resolve(ROOT, relPath), "utf-8"))
}

function writeJson(relPath, obj) {
  writeFileSync(resolve(ROOT, relPath), JSON.stringify(obj, null, 2) + "\n")
}

function readText(relPath) {
  return readFileSync(resolve(ROOT, relPath), "utf-8")
}

function writeText(relPath, content) {
  writeFileSync(resolve(ROOT, relPath), content)
}

// ── Resolve version ──────────────────────────────────────────────────

const SEMVER_RE = /^\d+\.\d+\.\d+$/
const BUMP_TYPES = ["patch", "minor", "major"]

function bumpVersion(current, type) {
  const [major, minor, patch] = current.split(".").map(Number)
  switch (type) {
    case "major":
      return `${major + 1}.0.0`
    case "minor":
      return `${major}.${minor + 1}.0`
    case "patch":
      return `${major}.${minor}.${patch + 1}`
  }
}

const arg = process.argv[2]

if (!arg) {
  const pkg = readJson("package.json")
  console.error(
    `\nUsage:  npm run release -- <patch|minor|major|x.y.z>\n\n` +
      `Current version: ${pkg.version}\n`
  )
  process.exit(1)
}

let newVersion

if (BUMP_TYPES.includes(arg)) {
  const pkg = readJson("package.json")
  newVersion = bumpVersion(pkg.version, arg)
} else if (SEMVER_RE.test(arg)) {
  newVersion = arg
} else {
  console.error(
    `\nError: "${arg}" is not a valid bump type (patch, minor, major) or semver version (x.y.z).\n`
  )
  process.exit(1)
}

// Ensure clean working tree
try {
  execSync("git diff --quiet && git diff --cached --quiet", { cwd: ROOT })
} catch {
  console.error(
    "\nError: Working tree has uncommitted changes. Please commit or stash them first.\n"
  )
  process.exit(1)
}

// ── Read current version ─────────────────────────────────────────────

const pkg = readJson("package.json")
const currentVersion = pkg.version

if (newVersion === currentVersion) {
  console.error(
    `\nError: New version (${newVersion}) is the same as the current version.\n`
  )
  process.exit(1)
}

console.log(`\nSafeDrive release: ${currentVersion} → ${newVersion}\n`)

// ── Update version in all manifest files ─────────────────────────────

// 1. package.json
console.log("Updating package.json …")
pkg.version = newVersion
writeJson("package.json", pkg)

// 2. package-lock.json (root + packages[""] entry)
console.log("Updating package-lock.json …")
const lock = readJson("package-lock.json")
lock.version = newVersion
if (lock.packages?.[""]?.version) {
  lock.packages[""].version = newVersion
}
writeJson("package-lock.json", lock)

// 3. src-tauri/tauri.conf.json
console.log("Updating src-tauri/tauri.conf.json …")
const tauriConf = readJson("src-tauri/tauri.conf.json")
tauriConf.version = newVersion
writeJson("src-tauri/tauri.conf.json", tauriConf)

// 4. src-tauri/Cargo.toml
console.log("Updating src-tauri/Cargo.toml …")
const cargoToml = readText("src-tauri/Cargo.toml")
const updatedCargoToml = cargoToml.replace(
  /^(version\s*=\s*")[\d.]+(")/m,
  `$1${newVersion}$2`
)
writeText("src-tauri/Cargo.toml", updatedCargoToml)

// 5. src-tauri/Cargo.lock
console.log("Updating src-tauri/Cargo.lock …")
const cargoLock = readText("src-tauri/Cargo.lock")
const updatedCargoLock = cargoLock.replace(
  /(name = "safedrive"\nversion = ")[\d.]+(")/,
  `$1${newVersion}$2`
)
writeText("src-tauri/Cargo.lock", updatedCargoLock)

// ── Git commit, tag, and push ────────────────────────────────────────

const tag = `v${newVersion}`

console.log("\nCommitting version bump …")
run("git add package.json package-lock.json src-tauri/tauri.conf.json src-tauri/Cargo.toml src-tauri/Cargo.lock")
run(`git commit -m "chore: bump version to ${newVersion}"`)

console.log(`\nTagging ${tag} …`)
run(`git tag ${tag}`)

console.log("\nPushing commit and tag …")
run("git push")
run(`git push origin ${tag}`)

console.log(`\n✅ Released ${tag} — GitHub Actions will build the release.\n`)
