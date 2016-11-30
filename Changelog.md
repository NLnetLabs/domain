## 0.2.0 [to be released]

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

Bug fixes


New


## 0.1.0

Initial public release.
