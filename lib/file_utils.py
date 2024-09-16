import os
import re

from typing import List, Union, Optional


def pattern_matching(
    pattern: Optional[Union[str, List[str]]], text: str, default: bool = True
):
    if pattern is None:
        return bool(default)
    if not isinstance(pattern, list):
        pattern = [pattern]
    for patt in pattern:
        match = re.search(patt, text)
        if match is not None:
            return True
    return False


def check_for_ignore(
    path: str,
    ignore_pattern: Optional[Union[str, List[str]]] = None,
    include_pattern: Optional[Union[str, List[str]]] = None,
    include_over_ignore: bool = True,
):
    is_ignore = False
    if include_over_ignore:
        should_ignore = pattern_matching(ignore_pattern, path, default=False)
        if should_ignore is True:
            is_ignore = True
            should_include = pattern_matching(include_pattern, path, default=False)
            if should_include is True:
                is_ignore = False
    else:
        should_include = pattern_matching(include_pattern, path, default=False)
        if should_include is True:
            should_ignore = pattern_matching(ignore_pattern, path, default=False)
            if should_ignore is True:
                is_ignore = True
        else:
            is_ignore = True
    return is_ignore


def format_print_path(path: str, max_line_len: int = -1, ellipsis: str = "..."):
    if max_line_len <= 0:
        return path
    if len(path) <= max_line_len:
        return path
    if max_line_len <= len(ellipsis):
        return path[-max_line_len:]
    allowed_len = max_line_len - len(ellipsis)
    formatted_print_path = ellipsis + path[-allowed_len:]
    return formatted_print_path


def list_files(
    file_path: str,
    ignore_pattern: Optional[str] = None,
    include_pattern: Optional[str] = None,
    include_over_ignore: bool = True,
):
    file_path = os.path.abspath(file_path)
    stack = [file_path]
    sequence = []
    while stack:
        f = stack.pop()
        if check_for_ignore(
            f,
            ignore_pattern=ignore_pattern,
            include_pattern=include_pattern,
            include_over_ignore=include_over_ignore,
        ):
            continue
        sequence.append(f)
        if os.path.isdir(f):
            subpaths = os.listdir(f)
            subpaths = [os.path.join(f, p) for p in subpaths]
            subpaths = [p for p in subpaths if os.path.isfile(p) or os.path.isdir(p)]
            stack.extend(subpaths)
    return sequence
