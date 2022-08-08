## Installation
1. Install pre-commit by following the instructions on https://pre-commit.com/#install
2. Create `.pre-commit-config.yaml` in your local root repository with the following content:

   ```
   repos:
     - repo: https://github.com/Kevino135/skripsi
       rev: 0.2.0.0
       hooks:
         - id: gitSanity
           stages: [commit]
         - id: gitSanityPull
           always_run: true
           stages: [post-merge]
         - id: gitSanityPush
           stages: [push]
   ```
3. Run `pre-commit install -t pre-commit -t post-merge -t pre-push` in your repository via CLI
4. Run `pre-commit autoupdate --repo https://github.com/Kevino135/skripsi`

## Pre-commit hook
If the tool detects a potential credential, a window will popup
User can choose to
1. Continue with encryption
   > If user chooses to continue with encryption, user will be prompted to enter an encryption key and select which issues to encrypt.
2. Continue without encryption
   > If user chooses to continue without encryption, user will be prompted to confirm.
3. Cancel
   > If user chooses to cancel, program exits with exit code 1.

## Pre-push hook
The tool pushes the commit, then scans all files in the repository, if it detects an encrypted string (fernet), a window will popup.
User will be prompted to input the decryption key (same key used for encryption)

## Post-merge hook
The tool scans all files in the repository, if it detects an encrypted string (fernet), a window will popup.
User will be prompted to input the decryption key (same key used for encryption)
