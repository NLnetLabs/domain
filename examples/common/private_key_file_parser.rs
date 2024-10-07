use domain::base::iana::SecAlg;
use domain::utils::base64;
use std::slice::Iter;
use super::error::Error;

fn parse_next_line<'a>(lines: &mut Iter<&'a str>, match_text: &str) -> Result<&'a str, Error> {
    if let Some(line) = lines.next() {
        if !line.starts_with(match_text) {
            return Err(Error::from(format!(
                "expected line starting with {}",
                match_text
            )));
        }

        if let Some((_, m)) = line.split_once(' ') {
            Ok(m)
        } else {
            return Err(Error::from("malformed line"));
        }
    } else {
        return Err(Error::from("expected more private key data"));
    }
}

#[derive(Default, Debug)]
pub struct RsaKeyData {
    algorithm_id: u8,
    modulus: Vec<u8>,
    public_exponent: Vec<u8>,
    private_exponent: Vec<u8>,
    prime1: Vec<u8>,
    prime2: Vec<u8>,
    exponent1: Vec<u8>,
    exponent2: Vec<u8>,
    coefficient: Vec<u8>,
}

impl RsaKeyData {
    fn parse_lines(algorithm: u8, lines: &mut Iter<&str>) -> Result<RsaKeyData, Error> {
        let modulus = parse_next_line(lines, "Modulus: ")?;
        let public_exponent = parse_next_line(lines, "PublicExponent: ")?;
        let private_exponent = parse_next_line(lines, "PrivateExponent: ")?;
        let prime1 = parse_next_line(lines, "Prime1: ")?;
        let prime2 = parse_next_line(lines, "Prime2: ")?;
        let exponent1 = parse_next_line(lines, "Exponent1: ")?;
        let exponent2 = parse_next_line(lines, "Exponent2: ")?;
        let coefficient = parse_next_line(lines, "Coefficient: ")?;

        Ok(RsaKeyData {
            algorithm_id: algorithm,
            modulus: base64::decode(modulus).expect("failed decoding base64 data"),
            public_exponent: base64::decode(public_exponent).expect("failed decoding base64 data"),
            private_exponent: base64::decode(private_exponent)
                .expect("failed decoding base64 data"),
            prime1: base64::decode(prime1).expect("failed decoding base64 data"),
            prime2: base64::decode(prime2).expect("failed decoding base64 data"),
            exponent1: base64::decode(exponent1).expect("failed decoding base64 data"),
            exponent2: base64::decode(exponent2).expect("failed decoding base64 data"),
            coefficient: base64::decode(coefficient).expect("failed decoding base64 data"),
        })
    }
}

#[derive(Default, Debug)]
pub struct EcKeyData {
    algorithm_id: u8,
    private_key: Vec<u8>,
}

impl EcKeyData {
    pub fn new(algorithm_id: u8, private_key: Vec<u8>) -> Self {
        Self { algorithm_id, private_key }
    }
    
    fn parse_lines(algorithm: u8, lines: &mut Iter<&str>) -> Result<EcKeyData, Error> {
        let private_key = parse_next_line(lines, "PrivateKey: ")?;

        Ok(EcKeyData {
            algorithm_id: algorithm,
            private_key: base64::decode(private_key).expect("failed decoding base64 data"),
        })
    }
    
    pub fn algorithm_id(&self) -> u8 {
        self.algorithm_id
    }
    
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
}

#[derive(Default, Debug)]
pub struct HmacKeyData {
    algorithm_id: u8,
    key: Vec<u8>,
}

impl HmacKeyData {
    fn parse_lines(algorithm: u8, lines: &mut Iter<&str>) -> Result<HmacKeyData, Error> {
        let key = parse_next_line(lines, "Key: ")?;

        Ok(HmacKeyData {
            algorithm_id: algorithm,
            key: base64::decode(key).expect("failed decoding base64 data"),
        })
    }
}

#[derive(Default, Debug)]
pub struct DsaKeyData {
    algorithm_id: u8,
    prime: Vec<u8>,
    subprime: Vec<u8>,
    base: Vec<u8>,
    private_value: Vec<u8>,
    public_value: Vec<u8>,
}

impl DsaKeyData {
    fn parse_lines(algorithm: u8, lines: &mut Iter<&str>) -> Result<DsaKeyData, Error> {
        let prime = parse_next_line(lines, "Prime(p): ")?;
        let subprime = parse_next_line(lines, "Subprime(q): ")?;
        let base = parse_next_line(lines, "Base(g): ")?;
        let private_value = parse_next_line(lines, "Private_value(x): ")?;
        let public_value = parse_next_line(lines, "Public_value(y): ")?;

        Ok(DsaKeyData {
            algorithm_id: algorithm,
            prime: base64::decode(prime).expect("failed decoding base64 data"),
            subprime: base64::decode(subprime).expect("failed decoding base64 data"),
            base: base64::decode(base).expect("failed decoding base64 data"),
            private_value: base64::decode(private_value).expect("failed decoding base64 data"),
            public_value: base64::decode(public_value).expect("failed decoding base64 data"),
        })
    }
}

#[derive(Debug)]
pub enum KeyData {
    Rsa(RsaKeyData),
    Ec(EcKeyData),
    Hmac(HmacKeyData),
    Dsa(DsaKeyData),
}

impl KeyData {
    /// Generate the Private-key-format text representation of KeyData
    pub fn gen_private_key_file_text(&self) -> Result<String, Error> {
        match &self {
            KeyData::Rsa(rsa) => Ok(format!(
                "Private-key-format: v1.2\n\
                Algorithm: {alg_id} ({alg_name})\n\
                Modulus: {modulus}\n\
                PublicExponent: {pub_exp}\n\
                PrivateExponent: {priv_exp}\n\
                Prime1: {prime1}\n\
                Prime2: {prime2}\n\
                Exponent1: {exp1}\n\
                Exponent2: {exp2}\n\
                Coefficient: {coeff}\n",
                alg_id = rsa.algorithm_id,
                alg_name = SecAlg::from_int(rsa.algorithm_id),
                modulus = base64::encode_string(&rsa.modulus),
                pub_exp = base64::encode_string(&rsa.public_exponent),
                priv_exp = base64::encode_string(&rsa.private_exponent),
                prime1 = base64::encode_string(&rsa.prime1),
                prime2 = base64::encode_string(&rsa.prime2),
                exp1 = base64::encode_string(&rsa.exponent1),
                exp2 = base64::encode_string(&rsa.exponent2),
                coeff = base64::encode_string(&rsa.coefficient),
            )),
            KeyData::Ec(ec) => Ok(format!(
                "Private-key-format: v1.2\n\
                Algorithm: {alg_id} ({alg_name})\n\
                PrivateKey: {key}\n",
                alg_id = ec.algorithm_id,
                alg_name = SecAlg::from_int(ec.algorithm_id),
                key = base64::encode_string(&ec.private_key),
            )),
            KeyData::Hmac(hmac) => Ok(format!(
                "Private-key-format: v1.2\n\
                Algorithm: {alg_id} ({alg_name})\n\
                Key: {key}\n",
                alg_id = hmac.algorithm_id,
                alg_name = match hmac.algorithm_id {
                    157 => "HMAC_MD5",
                    158 => "HMAC_SHA1",
                    159 => "HMAC_SHA256",
                    161 => "HMAC_SHA1",
                    162 => "HMAC_SHA224",
                    163 => "HMAC_SHA256",
                    164 => "HMAC_SHA384",
                    165 => "HMAC_SHA512",
                    _ => return Err(Error::from("unknown hmac algorithm")),
                },
                key = base64::encode_string(&hmac.key),
            )),
            KeyData::Dsa(dsa) => Ok(format!(
                "Private-key-format: v1.2\n\
                Algorithm: {alg_id} ({alg_name})\n\
                Prime(p): {p}\n\
                Subprime(q): {q}\n\
                Base(g): {g}\n\
                Private_value(x): {x}\n\
                Public_value(y): {y}\n",
                alg_id = dsa.algorithm_id,
                alg_name = SecAlg::from_int(dsa.algorithm_id),
                p = base64::encode_string(&dsa.prime),
                q = base64::encode_string(&dsa.subprime),
                g = base64::encode_string(&dsa.base),
                x = base64::encode_string(&dsa.private_value),
                y = base64::encode_string(&dsa.public_value),
            )),
        }
    }

    /// Parses lines of a private key file in bind's Private-key-format v1.x
    pub fn parse_lines(mut lines: Iter<&str>) -> Result<KeyData, Error> {
        // File format in ABNF (no data validity encoded here)

        // KEYFILE      = HEADER ALGORITHM KEY_SPECIFIC
        // HEADER       = %s"Private-key-format: v" DIGIT "." DIGIT LF
        // ALGORITHM    = %s"Algorithm: " 1*3DIGIT *1( " (" ALG_NAME ")" ) LF
        // KEY_SPECIFIC = RSA / EDDSA / HMAC / DSA
        //
        // RSA   = MODULUS PUBLIC_EXPONENT PRIVATE_EXPONENT PRIME1 PRIME2 EXPONENT1 EXPONENT2 COEFFICIENT
        // DSA   = PRIME SUBPRIME BASE PRIVATE_VALUE PUBLIC_VALUE
        // EDDSA = %s"PrivateKey: " BASE64_DATA
        // HMAC  = %s"Key: " BASE64_DATA
        //
        // PRIME            = %s"Prime(p): "         BASE64_DATA LF
        // SUBPRIME         = %s"Subprime(q): "      BASE64_DATA LF
        // BASE             = %s"Base(g): "          BASE64_DATA LF
        // PRIVATE_VALUE    = %s"Private_value(x): " BASE64_DATA LF
        // PUBLIC_VALUE     = %s"Public_value(y): "  BASE64_DATA LF
        //
        // MODULUS          = %s"Modulus: "          BASE64_DATA LF
        // PUBLIC_EXPONENT  = %s"PublicExponent: "   BASE64_DATA LF
        // PRIVATE_EXPONENT = %s"PrivateExponent: "  BASE64_DATA LF
        // PRIME1           = %s"Prim1: "            BASE64_DATA LF
        // PRIME2           = %s"Prime2: "           BASE64_DATA LF
        // EXPONENT1        = %s"Exponent1: "        BASE64_DATA LF
        // EXPONENT2        = %s"Exponent2: "        BASE64_DATA LF
        // COEFFICIENT      = %s"Coefficient: "      BASE64_DATA LF
        //
        // BASE64_DATA = *(ALPHA / DIGIT / "/" / "+")

        let mut algorithm = 0;

        if let Some(line) = lines.next() {
            if !line.starts_with("Private-key-format: v1.") {
                return Err(Error::from(
                    "expected private key format version (v1.x) specifier",
                ));
            }
        };

        if let Some(line) = lines.next() {
            if !line.starts_with("Algorithm: ") {
                return Err(Error::from("expected algorithm specifier"));
            }

            // "Algorithm: 123 (NAMEXYZ)"
            let mut parts = line.split(' ');
            parts.next(); // "Algorithm:"
            if let Some(alg) = parts.next() {
                algorithm = alg.parse()?;
            } else {
                return Err(Error::from("expected algorithm identifier number"));
            }
        };

        match SecAlg::from_int(algorithm) {
            SecAlg::RSAMD5
            | SecAlg::RSASHA1
            | SecAlg::RSASHA1_NSEC3_SHA1
            | SecAlg::RSASHA256
            | SecAlg::RSASHA512 => Ok(KeyData::Rsa(RsaKeyData::parse_lines(
                algorithm, &mut lines,
            )?)),
            SecAlg::DSA | SecAlg::DSA_NSEC3_SHA1 => Ok(KeyData::Dsa(DsaKeyData::parse_lines(
                algorithm, &mut lines,
            )?)),
            SecAlg::ECDSAP256SHA256 | SecAlg::ECDSAP384SHA384 | SecAlg::ED25519 | SecAlg::ED448 => {
                Ok(KeyData::Ec(EcKeyData::parse_lines(algorithm, &mut lines)?))
            }

            /* might be a hmac algorithm */
            _ => match algorithm {
                157 /* HMAC_MD5 */
                | 158 /* HMAC_SHA1 */
                | 159 /* HMAC_SHA256 */
                | 161 /* HMAC_SHA1 */
                | 162 /* HMAC_SHA224 */
                | 163 /* HMAC_SHA256 */
                | 164 /* HMAC_SHA384 */
                | 165 /* HMAC_SHA512 */
                => Ok(KeyData::Hmac(HmacKeyData::parse_lines(algorithm, &mut lines)?)),
                /* unknown algorithm number */
                _ => Err(Error::from("unsupported algorithm")),
            },
        }
    }
}