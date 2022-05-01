#!/usr/bin/env python3

import os

git_root = str(os.popen("git rev-parse --show-toplevel").read()).strip()

pre_commit_path = git_root + "/.git/hooks/pre-commit"
post_merge_path = git_root + "/.git/hooks/post-merge"
pre_push_path = git_root + "/.git/hooks/pre-push"

target_1 = 'exec "$INSTALL_PYTHON" -mpre_commit "${ARGS[@]}"'
target_2 = 'exec pre-commit "${ARGS[@]}"'

with open(pre_commit_path) as f: pre_commit = f.read()
with open(post_merge_path) as f: post_merge = f.read()
with open(pre_push_path) as f: pre_push = f.read()

pre_commit = pre_commit.replace(target_1, target_1 + " /dev/null").replace(target_2, target_2 + " /dev/null")
post_merge = post_merge.replace(target_1, target_1 + " /dev/null").replace(target_2, target_2 + " /dev/null")
pre_push   = pre_push.replace(target_1, target_1 + " /dev/null").replace(target_2, target_2 + " /dev/null")

with open(pre_commit_path, "w") as f: f.write(pre_commit)
with open(post_merge_path, "w") as f: f.write(post_merge)
with open(pre_push_path, "w") as f: f.write(pre_push)      