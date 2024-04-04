**The KES project welcomes all contributors.**

This document is a guide to help you getting your pull request merged more
quickly.

### Source Code

KES is (mostly) written in Go. The following resources may be valuable
to reduce code-review iterations:
 - [Code Formatting](https://github.com/mvdan/gofumpt) - KES uses `gofumpt` instead of `gofmt` or `goimports`.
 - [Go Style Guide](https://google.github.io/styleguide/go/decisions)
 - [Code Comments and Documentation](https://go.dev/doc/comment)
 - [Go Best Practices](https://github.com/golang/go/wiki/CodeReviewComments)

### Commit Message

The commit message explains **what** a change does and **why** it was needed.

Others, including yourself, may refer to the commit message to understand the
purpose of a commit. A good commit message can safe many hours or days of work
in the future.

For example:
```
a one line summary of the commit

First, explain why a change is needed if it isn't self-describing. 
Then talk about what a change does and its potential side-effects
before explaining the the design decisions. For example, explain
why you have chosen approach A instead of B. 

List assumptions / invariants that your change relies on. For example,
that some initialization logic assumes that it operations on a clean
state.

Include benchmarks when claiming a performance gain or loss.

Reference related commits, pull requests or issues. For example:

Ref: #101
Ref: a2b1987

When fixing an issue, include the issue number. The following directive
automatically references and automatically closes the issue on merge:

Fixes #102
```

### License

KES is an opensource project licensed under AGPLv3. The license file
can be found [here](https://github.com/minio/kes/blob/master/LICENSE).

By contributing to KES, you agree to assign the copyright to MinIO.
Any contributed source file must include the following license
header:
```
// Copyright <YEAR> - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.
 ```
