# Change Log


## Unreleased next version

Breaking Changes

New

Bug Fixes

Dependencies



## 0.5.0

Breaking Changes

* Migrated to use async functions. This allowed the resolver to use
  regular references instead of hiding behind arcs. ([#43])

Bug fixes

* Fix a panic if the end of the server list is reached during a query.
  Reported by [@dvc94ch]. [(#14)]
* Fix a panic when a server list is empty to begin with. (Fixes by
  [@vendemiat] in [#26])

Dependencies

* The crate now requires tokio 0.2 and futures 0.3.

[(#14)]: https://github.com/NLnetLabs/domain/pull/14
[#26]: https://github.com/NLnetLabs/domain/pull/26
[#42]: https://github.com/NLnetLabs/domain/pull/42
[@dvc94ch]: https://github.com/dvc94ch
[@vendemiat]: https://github.com/vendemiat


## 0.4.0

* Initial release.

