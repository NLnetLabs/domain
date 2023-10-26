# Contributing to _domain_

This document contains information for contributing to and maintaining the
_domain_ crate.

This is a first draft version. Feel free to, er, contribute to it.


## Submitting contributions

### Pull requests

#### When is a pull request required?

All changes to code and documentation have to go through pull requests.
Exceptions are minor modification that don’t actually change the code or
content of documentation. Examples are small changes suggested by Clippy or
spelling fixes or adding missing words in documentation.

#### Creating a pull request

The title and description of the pull request will be used in the commit
message when merging the request.

The title should therefore be less than about 70 characters long and
describe the change made by the pull request in a terse way.

The description should describe in detail what the pull request changes.
If the pull request results in a breaking change, the description should
note that.


## Code organization and formatting

### Repository structure

#### Branches and tags

The _main_ branch contains the current status of the crate. It has to be
kept in a state that builds cleanly as indicated by the CI workflow
succeeding. If the branch is ‘broken,’ it should be fixed as soon as
possible. As a consequence, it should generally be okay to use this branch
as a git dependency in a Cargo.toml.

Each release version is tagged with an annotated tag named `v0.x.y`. This tag
is referencing the merge commit of the PR for that release.

If changes need to be backported to an older version of the crate, start a
`series-0.x` branch from the release tag of the last release of that series.
This branch can be deleted once a release with the backported changes has
been made.

All other branches that do not have a pull request associated with them
can and should be deleted to keep the repository clean. Use a draft PR to
signal that you want to keep a branch around.

### Code structure

The main purpose of all of the following is to make it as easy as possible
for a reader to find what they are looking for and understand how things
work. Remember, that reader will likely be future you.

#### Module structure

Code within a module is grouped by “primary,” i.e., function or type.
Impl blocks are kept with the type they belong to. Private functions are
kept either with the public function they serve or, if they are used by
multiple functions or by methods in impl blocks, go into a “Helper functions”
primary of their own.

Primaries are separated by a comment consisting of two slashes, 11 hyphens, a
space, the name of the type, function or other primary, another space, and
as many hyphens as necessary to fill the line up to 78 characters. For
instance:

```
//----------- FooIter --------------------------------------------------------
```

This separator makes it easier to see where something new starts when
scrolling through a file. It also allows to search for the start of a
certain primary by searching for, e.g., `-- FooIter`.

Multiple primaries can be grouped with a similar separator that uses equals
signs instead of hyphens if that makes sense. For instance, all error
types are usually collected into a group titled “Error types.”

Primaries are ordered semantically with the most important items going first
and items used by other items generally below them. This requires a bit of
consideration. The idea is that reading through a file top to bottom kind
of makes sense. It should be as easy as possible for a reader to make
sense of the file.

Within primaries, sections can be created by using a subheading consisting of
two slashes, three hyphens, a space, and a heading title. For instance,
trait impls for a type are collected in semantically similar groups:

```
//--- AsRef, AsMut, Borrow, and BorrowMut
```

#### Impl blocks

The methods of a given type should be split over multiple thematic impl
blocks. They should be thematically arranged within the blocks as well,
keeping things together that do similar things. If there are lots of
methods, consider adding a docstring with a first level heading to the
beginning of an impl block that starts a new topic as that will be shown
in the rustdoc output.

The order of impl blocks is roughly: associated functions that create
values, methods converting values, other groups of methods, trait impls for
`From<_>` and `TryFrom<_>`, trait impls for conversion traits, other
trait impls.


#### Docstrings

Every item, field, variant, and function should have a docstring attached to
it, including private items. This is helpful since many editors mark
docstrings and comments differently, highlighting docstring as more important.

The docstring itself should consist of a headline giving a short summary
of the purpose of the element is. This really is only a single line which 
forces it to stay short. More information can be given in additional lines
separated by an empty docstring line. This information should include
everything that may be odd or unexpected about the use of the element.

For functions, the docstring should follow the usual rustdoc requirements,
such as using the active voice in third person or including the ‘Panics’ or
‘Safety’ sections if applicable.


#### Comments

Ideally, code is straightforward enough to not require any comments other
than the docstrings relaying the purpose. Consider breaking up complex code
into separate functions with meaningful names to make it obvious what
the code is doing and allow a reader to more easily pick the part they are
interested in.

If your code is complicated or non-obvious, consider having an
introductory comment for code blocks that explain what is going to happen
in broad strokes. If, upon reading a certain piece of code, you have a hard
time figuring out what it does, consider adding such a comment once you did.


### Code formatting

We’re using the standard formatting as created by rustfmt with two
exceptions that are reflected in `rustfmt.toml`:

#### Line length 78

The maximum line length is set to 78 characters. (This is to support a
workflow that keeps multiple editor windows side-by-side on screen.)

#### Imports

Imports are not automatically reordered and must be sorted manually. We
sort them alphabetically in a series of groups: `core`, `std`, extern
crates, `crate`, `super`. There are no empty lines between groups.

Each import statement contains one or more items from one module. I.e.,
imports from sub-modules aren’t nested but get their own use statement.

All module, type, and function imports each get their own use statements
with imported items ordered alphabetically.

For example:

```rust
use std::{fs, io};
use std::fs::{File, Metadata};
use std::fs::create_dir_all;
```

## Maintaining the crate

### Pull requests

Pull requests that contain more than trivial changes need to be reviewed
by a core team member other than the person submitting the request. Pull
request created for maintenance reasons or that are obviously trivial
don’t need a review. Developer discretion is advised.

Before merging, consider whether a pull request contains breaking changes.
Be conservative when making a decision. Anything that may result in
someone’s compilation (with `-D warnings`) breaking because of a `cargo
update` should be considered breaking.

Pull requests are normally merged by way of squashing. The squash commit
(or merge commit if for some reason a merge was used) should have a commit
message that consists of the pull requests title followed by the pull
request’s number in parenthesis as the first line and the pull request’s
description after a blank line converted to plain text and reformatted to
a line length of 78 characters.

After merging, pull the main branch and update Changelog.md with a short
yet descriptive summary of what was changed. Assign it to one of the four
sections ‘Breaking changes’, ‘New’, ‘Bug fixes’, or ‘Other changes’. If
the pull request was the first breaking change, update the version number in
Cargo.toml to the next major version but keep the `-dev` suffix. Commit
these changes directly to the main branch.


### Releases

Here’s what needs to be done when making a release:

* Dependency updates

  Before making a release, check whether there are any outdated dependency
  versions and consider updating them in a separate pull request.

* Create a release branch.

  * Set the final version in `Cargo.toml` by removing the `-dev` suffix.

  * Finalize `Changelog.md` by adding the version and the release date.
    Remove empty sections.

  * Run `cargo package` to see if publishing would succeed.

* Create a pull request, wait for all CI to go green, merge into main.

  * The merge commit should have `Release 0.x.y.` as the title and the
    changelog entries converted to plain text as its description.

* Run `cargo publish`.

* Create and push the release tag.

  Use an annotated tag with the name as `v0.x.y`, the title as
  `Release 0.x.y.` and the changelog entries converted to plain text as
  the description.

* Create a release on Github.

  The release uses the release tag as its basis. It’s title should be
  `Release 0.x.y` and the description is a copy of the changelog entries
  for the release kept in Markdown. Note that you have to stitch
  together broken up lines because Github keeps line feeds within
  paragraphs for some reason.

* Create a “Bump version” commit on main.

  * Increase the version in `Cargo.toml` to the next patch version
    suffixed by `-dev`.

  * Add a new section “Unreleased next version” to `Changelog.md`. Also
    add the four sub-sections “Breaking changes”, “New”, “Bug fixes”, and
    “Other changes”.

