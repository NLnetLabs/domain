// Collection of usefull types.

// RFC 4033, Section 5 defines the security states of data:
pub enum ValidationState {
	Secure,
	Insecure,
	Bogus,
	Indeterminate,
}
