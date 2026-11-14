// SPDX-License-Identifier: CC0-1.0

//! `awsglue._bookmark`: the JOB BOOKMARK one run resumes its source reads from, and advances
//! when the script commits.
//!
//! "Glue tracks data that has already been processed during a previous run of an ETL job by
//! persisting state information from the job run. This persisted state information is called
//! a job bookmark." The option that decides whether a run uses one is the job argument
//! `--job-bookmark-option`, and the state is "keyed by the transformation context" each read
//! names — so a run with bookmarks enabled reads, for each transformation context, only the
//! source objects modified after the point the last committed run recorded, and
//! `job.commit()` is what advances that point.
//!
//! This module holds that point for ONE run: the document the service stored for the job is
//! handed in before the script runs ([`super::super::job_script`] supplies it), the reader
//! consults it as it lists a path ([`super::table_data`]), and what the script's own commit
//! leaves is what the run answers with for the service to store against the job. Nothing
//! here persists anything itself: the bookmark a client reads through `GetJobBookmark` and
//! drops through `ResetJobBookmark` is the service's own record, so a reset leaves the next
//! run with no point to resume from and it reads every object again.

/// The source of `awsglue/_bookmark.py`.
pub(super) const BOOKMARK_SOURCE: &str = r#"
"""The job bookmark this run resumes from, and the point its own reads reach."""

import json

# "--job-bookmark-option" — "job-bookmark-enable | job-bookmark-disable |
# job-bookmark-pause" (AWS Glue's special job parameters). Enabled: the run reads only what
# is new to each transformation context and the script's commit advances the bookmark.
# Paused: it reads only what is new and leaves the bookmark where it is ("process state
# information from a previous run but don't update it"). Disabled, the documented default,
# is every object on every run.
OPTION_ARGUMENT = "job-bookmark-option"
ENABLE = "job-bookmark-enable"
PAUSE = "job-bookmark-pause"
DISABLE = "job-bookmark-disable"

# The member of the stored document holding one resume point per transformation context.
CONTEXTS = "contexts"

# How many transformation contexts ONE bookmark holds. The bounds that decide what a RUN may
# spend are the interpreter's, in host code; this keeps a script from asking this emulator to
# store an unbounded number of points, and a commit past it fails the run rather than storing
# a bookmark missing the contexts it did not fit.
MAX_CONTEXTS = 200

# What this run holds: the option it reads the bookmark under, the point each transformation
# context resumes from, the point each one has read UP TO in this run, and the document the
# script's own commit left for the service to store.
_run = {"option": DISABLE, "held": {}, "reached": {}, "committed": None}


def begin(stored):
    """Take up `stored`, the bookmark this job's last committed run left, for this run.

    Called once before the script runs. The OPTION is read off the run's own command line,
    which is where AWS Glue names it, through the one argument reading this library has.
    """
    import sys

    from awsglue.utils import _named_arguments

    named = _named_arguments(list(sys.argv))
    _run["option"] = str(named.get(OPTION_ARGUMENT) or DISABLE).strip() or DISABLE
    _run["held"] = _points(stored)
    _run["reached"] = {}
    _run["committed"] = None
    return None


def _points(stored):
    """The resume point per transformation context the stored document holds."""
    if not stored:
        return {}
    document = json.loads(stored)
    held = {}
    for context, point in (document.get(CONTEXTS) or {}).items():
        held[str(context)] = (int(point.get("modified") or 0), str(point.get("key") or ""))
    return held


def is_enabled():
    """Whether this run reads only what is new to each transformation context."""
    return _run["option"] in (ENABLE, PAUSE)


def advances():
    """Whether a commit of this run WRITES the bookmark, which only the enabled option does."""
    return _run["option"] == ENABLE


def unread(transformation_ctx, listed):
    """The listed `(key, size, modified)` objects this run reads, in listing order.

    Every one of them for a run the bookmark is not in force for, and for a read that names
    no transformation context: the state is keyed by that context, so a read naming none has
    no point to resume from. For a bookmarked read, the objects PAST the point the last
    committed run recorded for that context — an object whose last modified instant, and
    whose key where two objects share an instant, orders after it. The point this run reaches
    is kept as it reads, and the script's own commit is what asks for it to be stored.
    """
    if not transformation_ctx or not is_enabled():
        return list(listed)
    context = str(transformation_ctx)
    point = _run["held"].get(context)
    taken = []
    for key, size, modified in listed:
        at = (int(modified or 0), str(key))
        if point is not None and at <= point:
            continue
        taken.append((key, size, modified))
        reached = _run["reached"].get(context)
        if reached is None or at > reached:
            _run["reached"][context] = at
    return taken


def commit():
    """Advance the bookmark to the point this run's reads reached, as a commit asks.

    Called by `Job.commit()`, which is the point a script declares its work complete. A run
    the bookmark is paused or disabled for commits no point: the script's work is done either
    way, and the next run of the job resumes from where the last COMMITTED one left off.
    """
    if not advances():
        return None
    held = dict(_run["held"])
    held.update(_run["reached"])
    if len(held) > MAX_CONTEXTS:
        raise ValueError(
            "a job bookmark holds the resume points of at most %d transformation contexts; "
            "this commit would hold %d" % (MAX_CONTEXTS, len(held))
        )
    _run["committed"] = json.dumps(
        {
            CONTEXTS: dict(
                (context, {"modified": at[0], "key": at[1]})
                for context, at in held.items()
            )
        },
        sort_keys=True,
    )
    return None


def committed():
    """The document the script's own commit left for the service to store, else None."""
    return _run["committed"]
"#;
