#!/usr/bin/env python3

import os
import shutil
import sys


def copy_test_outputs(src_root: str, dest_root: str):
    """Prepares bazel test outputs from src_root into files at dest_root.

    The file patterns are converted into a format that is acceptable to Cloud
    Build ResultStore.

    See go/kokoro/userdocs/general/custom_test_logs.md#converting-bazel-test-logs-to-spongeresultstore-test-logs
    """
    for src_dir, _, files in os.walk(src_root, followlinks=True):
        dest_dir = os.path.join(
            dest_root, os.path.relpath(src_dir, src_root))
        for file_name in files:
            if file_name == 'test.log':
                os.makedirs(dest_dir, exist_ok=True)
                shutil.copyfile(os.path.join(src_dir, 'test.log'),
                                os.path.join(dest_dir, 'sponge_log.log'))
            if file_name == 'test.xml':
                os.makedirs(dest_dir, exist_ok=True)
                shutil.copyfile(os.path.join(src_dir, 'test.xml'),
                                os.path.join(dest_dir, 'sponge_log.xml'))


if __name__ == "__main__":
    copy_test_outputs(sys.argv[1], sys.argv[2])
