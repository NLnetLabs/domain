## 0.2.2

New

* `bits` module

   *  `bits::opt`` module for parsing and composing of OPT records and OPT
      options.

Bug fixes

* `resolver` module

   *  Resolver may crash with ‘rotate’ option and failing upstream servers.
      ([#20](https://github.com/partim/domain/issues/20)).

Dependencies

* updated tokio-core to 0.1.9.


## 0.2.1

Breaking Changes

* `bits` module

  *  `DNameBuf::from_iter` renamed to `DNameBuf::try_from_iter` to avoid
     confusing with `FromIterator` trait.

New

* `rdata` module

  *  Support for SRV records. (Thanks, @ThibG!)

* `resolver` module

  * Resolving server addresses with SRV records. (Thanks, @ThibG!)

Bug fixes

* `bits` module

  *  Correctly build later sections of a message in `MessageBuilder`.

Dependencies

* updated to futures 0.1.14 and tokio-core 0.1.8.


## 0.2.0

Breaking Changes

* `bits` module

  *  Domain name iterators have been reworked:

    * `NameLabels` and `NameLabelettes` are now `DoubleEndedIterator`s.

    * `RevNameLabels` and `RevNameLabelettes` are gone. Use the
      `next_back()` methods on the regular iterators instead.

    * `DName` has lost the `rev_labels()` and `rev_labelettes()` methods.
      
  *  Method name harmonization:

    *  `DNameSlice::iter()` is now `DNameSlice::labels()`,
    *  `ParsedDName::iter()` is now `ParsedDName::labels()`.

* `resolv` module

  *  Almost complete rewrite of the actual resolver to be compatible with
     tokio’s 0.1 release.

  *  `ResolverTask` is gone. You can now run queries directly on a
     resolver.

  *  The lookup functions now return a concrete type as their future
     instead of a boxed future. The names of their success types have been
     changed in order to harmonize names of future returning functions and
     the name of their returned types (as in `lookup_host()` returns a
     `LookupHost` as its future). The functionality of the success types
     has not changed.


Bug fixes


New


## 0.1.0

Initial public release.
