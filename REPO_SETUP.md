# How to Set Up W0lfSword as a GitHub Repo

## 1. Create the repo on GitHub

1. Go to https://github.com/new
2. Repository name: `W0lfSword`
3. Description: `iOS Kernel Exploit Toolkit — DarkSword Engine. Sandbox escape, SSV bypass, multi-app support. iOS 17.0–26.0.1.`
4. Public (or Private if you prefer)
5. Do NOT check "Add a README" — you already have one
6. Do NOT check ".gitignore" — you already have one
7. Click "Create repository"

## 2. Rename your local directory

```bash
cd /home/kaffein/Desktop
mv FilzaJailedDS-SSV-Bypass W0lfSword
cd W0lfSword
```

## 3. Update the remote origin

Your current remote points to XEmaz's fork. Change it to yours:

```bash
# Check current remote
git remote -v

# Change origin to YOUR new repo
git remote set-url origin https://github.com/YOUR_USERNAME/W0lfSword.git

# Optional: keep XEmaz as upstream to pull updates
git remote add upstream https://github.com/XEmaz/W0lfSword.git
```

## 4. First push

```bash
git add -A
git status                    # Review what's staged
git commit -m "W0lfSword v0.8 — initial release

DarkSword kernel exploit toolkit for iOS 17.0-26.0.1
- Kernel R/W via ICMPv6 socket spray + IOSurface physical OOB
- Sandbox escape via kernel extension table patching
- SSV bypass via vnode data pointer redirection
- Filza UI hooks (padlock, license, zip/unzip)
- iOS 26.0.1 stability fixes (13 applied)
- Arctic wolf themed CLI + interactive exploit menu
- Comprehensive documentation (ROADMAP, BUG_BOUNTY, DEBUG_TRACKING, CONTEXT)"

git push origin main
# If the branch is 'master' instead: git push origin master
```

## 5. Protect your main branch (optional)

On GitHub repo → Settings → Branches → Add branch protection rule:
- Branch name pattern: `main`
- Require pull request reviews before merging
- Require status checks to pass

## 6. Add a .gitignore

Create `.gitignore` if you don't have one:

```bash
cat > .gitignore << 'EOF'
.theos/
packages/
*.deb
*.dylib
W0lfSword.dylib
FilzaApplySandboxExt.dylib
.w0lfsword/
.device_ip
.DS_Store
*.swp
*.swo
*~
EOF
```

## 7. Daily workflow

```bash
# Pull latest changes
git pull origin main

# Make changes, then:
./W0lfSword audit           # Check nothing's broken
./W0lfSword status          # Review state
git add -A
git commit -m "fix: description of what changed"
git push origin main
```

---

## If You Want to Keep the Original FilzaJailedDS Name Too

Some projects keep the original directory name for backward compatibility:

```bash
# Option A: Rename only on GitHub, keep local dir name
# (local stays FilzaJailedDS-SSV-Bypass, GitHub shows W0lfSword)

# Option B: Symlink
ln -s ~/Desktop/W0lfSword ~/Desktop/FilzaJailedDS-SSV-Bypass
```

---

## Quick Sanity Checklist Before First Push

- [ ] No .theos/ build artifacts staged
- [ ] No packages/*.deb staged
- [ ] No API keys, passwords, or tokens in any file
- [ ] .device_ip is gitignored (has your device IP)
- [ ] README.md shows the correct repo URL (XEmaz/W0lfSword → YOUR_USERNAME/W0lfSword)
- [ ] Credits section acknowledges 34306 (original), XEmaz (current), kaffeindecaf (audit)
- [ ] Run `./W0lfSword audit` and `./W0lfSword status` — all clean
