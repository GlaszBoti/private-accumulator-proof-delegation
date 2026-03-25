use crate::traits::Group;
use curv::arithmetic::traits::*;
use curv::BigInt;
use sha256::digest;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Once, OnceLock};

pub use ::class_group::{
    bn_to_gen, pari_qf_comp_to_decimal_string, ABDeltaTriple, BinaryQF, BinaryQFCompressed,
};

pub use ::class_group::primitives;

static PARI_INIT: Once = Once::new();
static CLASS_GROUP_128_SETUP: OnceLock<ClassGroup> = OnceLock::new();

const CLASS_GROUP_LAMBDA_128: usize = 600;

fn ensure_pari_init() {
    PARI_INIT.call_once(|| unsafe {
        ::class_group::pari_init(100000000, 2);
    });
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassGroupElement(pub BinaryQF);

impl Hash for ClassGroupElement {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassGroupExponent(pub BigInt);

impl Hash for ClassGroupExponent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        BigInt::to_bytes(&self.0).hash(state);
    }
}

impl fmt::Display for ClassGroupExponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = BigInt::to_bytes(&self.0);
        if bytes.is_empty() {
            return write!(f, "0");
        }
        for b in bytes {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ClassGroup {
    pub discriminant: BigInt,
    pub generator: BinaryQF,
}

impl ClassGroup {
    pub fn from_params(discriminant: BigInt, generator_prime: BigInt) -> Self {
        ensure_pari_init();
        assert!(
            discriminant < BigInt::zero(),
            "discriminant must be negative"
        );
        assert_eq!(
            discriminant.mod_floor(&BigInt::from(4)),
            BigInt::one(),
            "discriminant must satisfy delta = 1 (mod 4)"
        );
        assert!(
            generator_prime > BigInt::one(),
            "generator_prime must be > 1"
        );
        assert!(
            generator_prime.mod_floor(&BigInt::from(2)) == BigInt::one(),
            "generator_prime must be odd"
        );

        let generator = BinaryQF::primeform(&discriminant, &generator_prime).reduce();
        Self {
            discriminant,
            generator,
        }
    }

    pub fn new(discriminant: BigInt, generator_prime: BigInt) -> Self {
        Self::from_params(discriminant, generator_prime)
    }

    pub fn setup_with_params(discriminant: BigInt, generator_prime: BigInt) -> Self {
        Self::from_params(discriminant, generator_prime)
    }

    pub fn setup_security() -> Self {
        CLASS_GROUP_128_SETUP
            .get_or_init(|| {
                ensure_pari_init();
                let seed_hex = digest(b"sadhflasdkjflasdkfhjlsdfhlsdfkhsldfhsdhlfksdhlfs");
                let seed = BigInt::from_str_radix(&seed_hex, 16)
                    .expect("seed hash must be parseable as hex bigint");
                let cl_group = primitives::cl_dl_public_setup::CLGroup::new_from_setup(
                    &CLASS_GROUP_LAMBDA_128,
                    &seed,
                );

                Self {
                    discriminant: cl_group.gq.discriminant(),
                    generator: cl_group.gq.reduce(),
                }
            })
            .clone()
    }

    pub fn principal(&self) -> BinaryQF {
        ensure_pari_init();
        BinaryQF::binary_quadratic_form_principal(&self.discriminant)
    }

    pub fn compose(&self, a: &BinaryQF, b: &BinaryQF) -> BinaryQF {
        ensure_pari_init();
        a.compose(b).reduce()
    }

    pub fn inverse(&self, element: &BinaryQF) -> BinaryQF {
        ensure_pari_init();
        element.inverse().reduce()
    }

    pub fn exp_qf(&self, base: &BinaryQF, exponent: &BigInt) -> BinaryQF {
        ensure_pari_init();
        base.exp(exponent).reduce()
    }

    pub fn hash_bytes_to_prime(data: &[u8]) -> BigInt {
        let hash_hex = digest(data);
        let mut candidate = BigInt::from_str_radix(&hash_hex, 16)
            .expect("sha256 digest must be parseable as a hex integer");

        if candidate.modulus(&BigInt::from(2)) == BigInt::zero() {
            candidate += BigInt::one();
        }

        while !primitives::is_prime(&candidate) {
            candidate += BigInt::from(2);
        }

        candidate
    }
}

impl Group for ClassGroup {
    type Element = ClassGroupElement;
    type Exponent = ClassGroupExponent;

    fn setup() -> Self {
        Self::setup_security()
    }

    fn g(&self) -> Self::Element {
        ClassGroupElement(self.generator.clone())
    }

    fn id(&self) -> Self::Element {
        ClassGroupElement(self.principal())
    }

    fn mul(&self, a: &Self::Element, b: &Self::Element) -> Self::Element {
        ClassGroupElement(self.compose(&a.0, &b.0))
    }

    fn inv(&self, element: &Self::Element) -> Self::Element {
        ClassGroupElement(self.inverse(&element.0))
    }

    fn exp(&self, base: &Self::Element, exponent: &Self::Exponent) -> Self::Element {
        ClassGroupElement(self.exp_qf(&base.0, &exponent.0))
    }

    fn exp_id() -> Self::Exponent {
        ClassGroupExponent(BigInt::one())
    }

    fn exp_mul(a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent {
        ClassGroupExponent(&a.0 * &b.0)
    }

    fn hash_to_prime(&self, data: &[u8]) -> Self::Exponent {
        ClassGroupExponent(Self::hash_bytes_to_prime(data))
    }
}
