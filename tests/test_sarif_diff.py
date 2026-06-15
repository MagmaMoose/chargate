"""Unit tests for the unified-diff parser (chargate.sarif.diff)."""

from __future__ import annotations

from chargate.sarif.diff import FileDiff, normalize_path, parse_unified_diff

# A realistic `git diff --unified=0 -M -C` patch exercising add/modify/delete/rename.
SAMPLE_DIFF = """\
diff --git a/src/new_file.py b/src/new_file.py
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/src/new_file.py
@@ -0,0 +1,3 @@
+import os
+
+print(os.getcwd())
diff --git a/src/modified.py b/src/modified.py
index 1111111..2222222 100644
--- a/src/modified.py
+++ b/src/modified.py
@@ -10 +10 @@ def foo():
-    return 1
+    return 2
@@ -20,0 +21,2 @@ def bar():
+    x = 1
+    y = 2
diff --git a/src/gone.py b/src/gone.py
deleted file mode 100644
index 3333333..0000000
--- a/src/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-a = 1
-b = 2
diff --git a/old/name.py b/new/name.py
similarity index 92%
rename from old/name.py
rename to new/name.py
index 4444444..5555555 100644
--- a/old/name.py
+++ b/new/name.py
@@ -5 +5 @@ class C:
-    value = 1
+    value = 2
"""


def test_normalize_path_variants():
    assert normalize_path("./src/app.py") == "src/app.py"
    assert normalize_path("src\\app.py") == "src/app.py"
    assert normalize_path('"src/with space.py"') == "src/with space.py"


def test_added_file_is_all_net_new():
    index = parse_unified_diff(SAMPLE_DIFF)
    new_file = index.get("src/new_file.py")
    assert new_file is not None
    assert new_file.is_new_file
    assert new_file.contains_line(1)
    assert new_file.contains_line(3)
    assert not new_file.contains_line(4)


def test_modified_hunks_capture_added_ranges():
    index = parse_unified_diff(SAMPLE_DIFF)
    modified = index.get("src/modified.py")
    assert modified is not None
    assert modified.status == "modified"
    # First hunk replaced line 10; second added lines 21..22.
    assert modified.contains_line(10)
    assert modified.contains_line(21)
    assert modified.contains_line(22)
    assert not modified.contains_line(11)
    assert not modified.contains_line(20)


def test_deleted_file_status():
    index = parse_unified_diff(SAMPLE_DIFF)
    gone = index.get("src/gone.py")
    assert gone is not None
    assert gone.is_deleted
    assert gone.added_ranges == ()


def test_rename_maps_old_to_new_path():
    index = parse_unified_diff(SAMPLE_DIFF)
    # SARIF URIs reference the head path, so the file is keyed by the new name.
    assert index.get("old/name.py") is None
    renamed = index.get("new/name.py")
    assert renamed is not None
    assert renamed.status == "renamed"
    assert renamed.old_path == "old/name.py"
    assert renamed.contains_line(5)


def test_pure_rename_without_content_change_has_no_added_lines():
    diff = """\
diff --git a/a.py b/b.py
similarity index 100%
rename from a.py
rename to b.py
"""
    index = parse_unified_diff(diff)
    renamed = index.get("b.py")
    assert renamed is not None
    assert renamed.status == "renamed"
    assert renamed.added_ranges == ()
    assert not renamed.contains_line(1)


def test_hunk_with_omitted_count_means_single_line():
    diff = """\
diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -3 +3 @@
-old
+new
"""
    index = parse_unified_diff(diff)
    x = index.get("x.py")
    assert x is not None
    assert x.contains_line(3)
    assert not x.contains_line(4)


def test_empty_diff_is_empty_index():
    index = parse_unified_diff("")
    assert len(index) == 0
    assert not index


def test_file_diff_is_frozen_and_hashable():
    fd = FileDiff(path="a.py", status="modified", added_ranges=((1, 2),))
    assert hash(fd) is not None
