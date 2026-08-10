# Tomorrow's Tasks — W0lfSword

## ⚡ Quick Wins (15 min each)

- [ ] Add `.gitignore`, stage all source files, first commit to your new GitHub repo
- [ ] Rename directory: `mv ~/Desktop/FilzaJailedDS-SSV-Bypass ~/Desktop/W0lfSword`
- [ ] Run `./W0lfSword doctor` — make sure build environment is ready

## 🐛 Bug Fixes

- [ ] `A1.2` — Audit all kread64 calls for missing xpaci() on arm64e (grep + manual review)
- [ ] `A1.6` — Thread offset verification: read kstackptr before any kwrite, validate against VM_MIN/VM_MAX
- [ ] `A2.2` — Padlock bypass: check if NZFileBrowserController class exists at load time

## 🧪 On Real Device

- [ ] Get a test device (iPhone SE 2022 on 17.x-18.x, or ask seller for iOS version)
- [ ] Install OpenSSH via Sileo/Cydia
- [ ] Run `./W0lfSword deploy <ip>` — first real deploy
- [ ] Check `/tmp/FilzaTweak.log` — confirm "SANDBOX ESCAPED" appears
- [ ] Test SSV write: create a file in /System/Library/ via Filza

## 📝 Documentation

- [ ] Update remote URL in README.md: `XEmaz/W0lfSword` → `YOUR_USERNAME/W0lfSword`
- [ ] Head to GitHub → Settings → Branch protection on `main`
- [ ] Add repo description and website link

---

> *Run `./W0lfSword status` when you open the project to see current state.*
