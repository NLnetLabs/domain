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
