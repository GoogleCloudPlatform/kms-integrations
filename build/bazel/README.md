# build/bazel

This workspace exists to facilitate building a later version of Bazel on
FreeBSD.

The only target is a thin genrule around compiling Bazel from source.

We take this approach so that it's straightforward to update to a new Bazel.
Note that all of the work of building Bazel from scratch shouldn't happen
often - the first time we build with a new Bazel version, the resulting binary
will be added to the remote cache.
