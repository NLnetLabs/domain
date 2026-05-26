
# Notes

## MNEMONIC PREFIX

- Class
- Rtype
- SvcParamKey

## INTEGER

- DigestAlgorithm
- IpseckeyAlgorithm
- IpseccGatewayType
- Nsec3HashAlgorithm
- SshfpAlgorithm
- SshfpType
- TlsaCertificateUsage
- TlsaMatchingType
- TlsaSelector
- ZonemdAlgorithm
- ZonemdScheme


## MNEMONIC with integer in parentheses for display

- OpCode
- OptionCode
- TsigRcode

## INTEGER with integer in parentheses for display

- SecurityAlgorithm


fn(
    type: struct
    integer_type: [u8, u16]
    default_represent: (Mnemonics, Integer, MnemonicPrefixed)
    display_trait: (Mnemonics, Integer, MnemonicWithIntegerInParentheses)
    prefix: str
)




trait IanaEnum {

  fn display_as_number() {
      
  }

  fn display_mnemonic()

  fn display_with_prefix() {
    const PREFIX: STRING = "CLASS"

  }

}


macro_rules! hello_world
... => {
    impl fmt::Display for $iana_type {
        $iana_type::$display_callable(f)
    }

    impl str::FromStr for $iana_type {
        $fromstr_callable(something: &str)
    }

}

iana_enum_implemenation!(SecAlg, IanaEnum::display_as_number, |f|)
