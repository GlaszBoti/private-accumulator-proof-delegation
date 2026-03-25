#[cfg(feature = "class-group")]
use crate::groups::class_group::{ClassGroup, ClassGroupElement, ClassGroupExponent};
use crate::nizk::NIZK;
use crate::rsa_group::RsaGroup;
use crate::traits::{
    Accumulator, Group, NonMembershipAccumulator, PrivatelyDelegatableAccumulator,
    PrivatelyDelegatableNonMembershipAccumulator,
};
#[cfg(feature = "class-group")]
use curv::arithmetic::Converter;
use glass_pumpkin::safe_prime;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use num_integer::ExtendedGcd;
use num_integer::Integer;
use num_traits::One;
use rand::thread_rng;
use std::collections::HashSet;

type Aux = ((BigUint, BigUint, BigUint), (BigUint, BigUint, BigUint));
type UpdatedBlindProof = ((BigUint, BigUint), Aux, BigUint);

extern crate primes;

const KEY_SIZE: u64 = 256; // This key size is just for demonstration

#[derive(Clone, Debug)]
pub struct GenericAccumulator<G: Group> {
    pub group: G,
    pub acc: G::Element,
    pub set: HashSet<G::Exponent>,
}

pub type RsaAccumulator = GenericAccumulator<RsaGroup>;

impl<G: Group> GenericAccumulator<G> {
    pub fn new(group: G) -> Self {
        let acc = group.g();
        Self {
            group,
            acc,
            set: HashSet::new(),
        }
    }

    pub fn value(&self) -> &G::Element {
        &self.acc
    }

    pub fn add<T: ToString>(&mut self, x: &T) -> G::Exponent {
        let x_str = x.to_string();
        let x_prime = self.group.hash_to_prime(x_str.as_bytes());

        if !self.set.contains(&x_prime) {
            self.set.insert(x_prime.clone());
            self.acc = self.group.exp(&self.acc, &x_prime);
        }
        x_prime
    }

    pub fn del<T: ToString>(&mut self, x: &T) {
        let x_str = x.to_string();
        let x_prime = self.group.hash_to_prime(x_str.as_bytes());

        if self.set.remove(&x_prime) {
            let product = self.calculate_product();
            self.acc = self.group.exp(&self.group.g(), &product);
        }
    }

    pub fn calculate_product(&self) -> G::Exponent {
        self.set
            .iter()
            .cloned()
            .fold(G::exp_id(), |acc, s| G::exp_mul(&acc, &s))
    }

    pub fn mem_proof_create(&self, x: &G::Exponent) -> G::Element {
        let prod = self
            .set
            .iter()
            .filter(|s| *s != x)
            .fold(G::exp_id(), |acc, s| G::exp_mul(&acc, &s));
        self.group.exp(&self.group.g(), &prod)
    }

    pub fn mem_ver(&self, proof: &G::Element, x: &G::Exponent) -> bool {
        self.group.exp(proof, x) == self.acc
    }

    pub fn blind_mem_proof(&self, mem_proof: &G::Element) -> (G::Element, G::Exponent) {
        let mut rng = thread_rng();
        let st = self
            .group
            .hash_to_prime(&rng.gen_biguint(128).to_bytes_be());
        let mask = self.group.exp(&self.group.g(), &st);
        let blinded_proof = self.group.mul(mem_proof, &mask);
        (blinded_proof, st)
    }

    pub fn unblind_mem_proof(&self, blinded_proof: &G::Element, st: &G::Exponent) -> G::Element {
        let st_mask = self.group.exp(&self.group.g(), st);
        let st_inv = self.group.inv(&st_mask);
        self.group.mul(blinded_proof, &st_inv)
    }
}

impl GenericAccumulator<RsaGroup> {
    pub fn setup() -> Self {
        let mut rng = rand::thread_rng();

        let p_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        let q_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        let p = BigUint::from(p_uint);
        let q = BigUint::from(q_uint);

        let n = &p * &q;
        let totient = (&p - BigUint::one()) * (&q - BigUint::one());

        let g = rng.gen_biguint_range(&BigUint::one(), &n);
        let group = RsaGroup::new(n, g, Some(totient));

        Self::new(group)
    }

    pub fn setup_trapdoorless() -> Self {
        let mut rng = rand::thread_rng();

        let p_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        let q_uint = safe_prime::new(KEY_SIZE as usize).unwrap();
        let p = BigUint::from(p_uint);
        let q = BigUint::from(q_uint);
        let n = &p * &q;

        let g = rng.gen_biguint_range(&BigUint::one(), &n);
        let group = RsaGroup::new(n, g, None);

        Self::new(group)
    }

    pub fn non_mem_proof_create(&self, x: &BigUint) -> (BigInt, BigUint) {
        let s = BigInt::from(self.calculate_product_unreduced());

        let x_str = x.to_string();
        let x_prime = self.group.hash_to_prime(x_str.as_bytes());
        let x_prime_int = BigInt::from(x_prime.clone());

        let ExtendedGcd { gcd, x, y } = Integer::extended_gcd(&s, &x_prime_int);
        assert_eq!(
            gcd,
            BigInt::one(),
            "non-member prime must be coprime with accumulator set product"
        );

        if let Some(t) = self.group.totient() {
            let totient_int = t.to_bigint().unwrap();
            let a = ((x % &totient_int) + &totient_int) % &totient_int;
            let b = (((y % &totient_int) + &totient_int) % &totient_int)
                .to_biguint()
                .unwrap();
            (a, self.group.exp(&self.group.g(), &b))
        } else {
            (x.clone(), self.group.signed_exp(&self.group.g(), &y))
        }
    }

    pub fn non_mem_ver(&self, proof: &(BigInt, BigUint), x: &BigUint) -> bool {
        let x_str = x.to_string();
        let x_prime = self.group.hash_to_prime(x_str.as_bytes());
        let lhs = self.group.signed_exp(&self.acc, &proof.0);
        let rhs = self.group.exp(&proof.1, &x_prime);
        self.group.mul(&lhs, &rhs) == self.group.g()
    }

    pub fn blind_mem_proof_upd(
        &self,
        elem_in: Vec<BigUint>,
        _elem_out: Vec<BigUint>,
        acc_t: &BigUint,
        blinded_proof: &BigUint,
    ) -> UpdatedBlindProof {
        let mut delta = BigUint::one();
        for elem in &elem_in {
            let x_str = elem.to_string();
            let x_prime = self.group.hash_to_prime(x_str.as_bytes());
            delta *= &x_prime;
        }

        let acct_tprime = &self.acc;
        let a = self.group.exp(blinded_proof, &delta);
        let g = self.group.g();
        let b = self.group.exp(&g, &delta);

        let nizk = NIZK::setup(&self.group);
        let pi1 = NIZK::prove_dleq(&nizk, blinded_proof, &a, acc_t, acct_tprime, &delta);
        let pi2 = NIZK::prove_dleq(&nizk, &g, &b, blinded_proof, &a, &delta);

        let upd_blinded_proof = (a, b);
        let aux = (pi1, pi2);
        (upd_blinded_proof, aux, acc_t.clone())
    }

    pub fn ver_blind_mem_proof_upd(
        &self,
        acc_t: &BigUint,
        blinded_proof: &BigUint,
        upd_blinded_proof: &(BigUint, BigUint),
        aux: &Aux,
    ) -> bool {
        let pi1 = &aux.0;
        let pi2 = &aux.1;

        let a = &upd_blinded_proof.0;
        let b = &upd_blinded_proof.1;
        let nizk = NIZK::setup(&self.group);
        let acct_tprime = &self.acc;
        let g = self.group.g();

        let d1 = NIZK::verify_dleq(&nizk, blinded_proof, a, acc_t, acct_tprime, pi1);
        let d2 = NIZK::verify_dleq(&nizk, &g, b, blinded_proof, a, pi2);
        d1 && d2
    }

    pub fn blind_non_mem_proof(&self, x: &BigUint) -> (BigUint, BigUint) {
        let x_str = x.to_string();
        let x_prime = self.group.hash_to_prime(x_str.as_bytes());

        if self.set.contains(&x_prime) {
            (BigUint::from(0u32), BigUint::from(1u32))
        } else {
            let mut rng = thread_rng();
            let s = self.calculate_product_unreduced();

            let q = loop {
                let seed = rng.gen_biguint(128);
                let q_candidate = self
                    .group
                    .hash_to_prime(seed.to_bytes_be().as_slice())
                    .to_biguint()
                    .unwrap();
                if q_candidate.gcd(&s) == BigUint::one() {
                    break q_candidate;
                }
            };

            let blinded_non_mem_proof = x_prime * &q;
            (blinded_non_mem_proof, q)
        }
    }

    pub fn blind_non_mem_proof_upd(&self, blinded_non_mem_proof: &BigUint) -> (BigInt, BigUint) {
        let s = BigInt::from(self.calculate_product_unreduced());

        let bnmp_str_int = BigInt::from(blinded_non_mem_proof.clone());
        let ExtendedGcd { gcd, x, y } = Integer::extended_gcd(&s, &bnmp_str_int);
        assert_eq!(
            gcd,
            BigInt::one(),
            "blinded value must be coprime with accumulator set product"
        );

        if let Some(t) = self.group.totient() {
            let totient_int = t.to_bigint().unwrap();
            let a = ((x % &totient_int) + &totient_int) % &totient_int;
            let b = (((y % &totient_int) + &totient_int) % &totient_int)
                .to_biguint()
                .unwrap();
            (a, self.group.exp(&self.group.g(), &b))
        } else {
            (x.clone(), self.group.signed_exp(&self.group.g(), &y))
        }
    }

    pub fn ver_blind_non_mem_proof_upd(
        &self,
        acc_t_prime: &BigUint,
        blinded_non_mem_proof: &BigUint,
        upd_blinded_non_mem_proof: &(BigInt, BigUint),
    ) -> bool {
        let a = &upd_blinded_non_mem_proof.0;
        let b = &upd_blinded_non_mem_proof.1;

        let lhs = self.group.signed_exp(acc_t_prime, a);
        let rhs = self.group.exp(b, blinded_non_mem_proof);
        self.group.mul(&lhs, &rhs) == self.group.g()
    }

    pub fn unblind_non_mem_proof(
        &self,
        st: &BigUint,
        upd_blinded_non_mem_proof: &(BigInt, BigUint),
    ) -> (BigInt, BigUint) {
        let a = &upd_blinded_non_mem_proof.0;
        let b = &upd_blinded_non_mem_proof.1;
        let b_prime = self.group.exp(b, st);

        (a.clone(), b_prime)
    }

    fn calculate_product_unreduced(&self) -> BigUint {
        self.set.iter().cloned().product()
    }
}

#[cfg(feature = "class-group")]
fn class_exp_to_num(exp: &ClassGroupExponent) -> BigInt {
    let bytes = curv::BigInt::to_bytes(&exp.0);
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes)
}

#[cfg(feature = "class-group")]
fn num_to_curv_signed(n: &BigInt) -> curv::BigInt {
    let (sign, bytes) = n.to_bytes_be();
    let v = curv::BigInt::from_bytes(&bytes);
    match sign {
        num_bigint::Sign::Minus => -v,
        num_bigint::Sign::NoSign | num_bigint::Sign::Plus => v,
    }
}

#[cfg(feature = "class-group")]
fn class_group_signed_exp(
    group: &ClassGroup,
    base: &ClassGroupElement,
    exponent: &BigInt,
) -> ClassGroupElement {
    if *exponent >= BigInt::from(0u32) {
        let exp = ClassGroupExponent(num_to_curv_signed(exponent));
        group.exp(base, &exp)
    } else {
        let abs_exp = -exponent;
        let exp = ClassGroupExponent(num_to_curv_signed(&abs_exp));
        let pos = group.exp(base, &exp);
        group.inv(&pos)
    }
}

#[cfg(feature = "class-group")]
impl GenericAccumulator<ClassGroup> {
    fn calculate_product_unreduced_class(&self) -> BigInt {
        self.set
            .iter()
            .map(class_exp_to_num)
            .fold(BigInt::one(), |acc, v| acc * v)
    }

    pub fn non_mem_proof_create_class(
        &self,
        x: &ClassGroupExponent,
    ) -> (BigInt, ClassGroupElement) {
        let s = self.calculate_product_unreduced_class();
        let x_num = class_exp_to_num(x);

        let ExtendedGcd { gcd, x: a, y: b } = Integer::extended_gcd(&s, &x_num);
        assert_eq!(
            gcd,
            BigInt::one(),
            "non-member prime must be coprime with accumulator set product"
        );

        let b_elem = class_group_signed_exp(&self.group, &self.group.g(), &b);
        (a, b_elem)
    }

    pub fn non_mem_ver_class(
        &self,
        proof: &(BigInt, ClassGroupElement),
        x: &ClassGroupExponent,
    ) -> bool {
        let lhs = class_group_signed_exp(&self.group, &self.acc, &proof.0);
        let rhs = self.group.exp(&proof.1, x);
        self.group.mul(&lhs, &rhs) == self.group.g()
    }
}

impl<G> Accumulator for GenericAccumulator<G>
where
    G: Group,
    G::Exponent: ToString,
{
    type Group = G;
    type Element = G::Exponent;
    type MembershipProof = G::Element;

    fn new(group: Self::Group) -> Self {
        GenericAccumulator::<G>::new(group)
    }

    fn add(&mut self, element: &Self::Element) -> <Self::Group as Group>::Exponent {
        GenericAccumulator::<G>::add(self, element)
    }

    fn del(&mut self, element: &Self::Element) {
        GenericAccumulator::<G>::del(self, element)
    }

    fn value(&self) -> &<Self::Group as Group>::Element {
        GenericAccumulator::<G>::value(self)
    }

    fn mem_proof_create(
        &self,
        element: &<Self::Group as Group>::Exponent,
    ) -> Self::MembershipProof {
        GenericAccumulator::<G>::mem_proof_create(self, element)
    }

    fn mem_ver(
        &self,
        proof: &Self::MembershipProof,
        element: &<Self::Group as Group>::Exponent,
    ) -> bool {
        GenericAccumulator::<G>::mem_ver(self, proof, element)
    }
}

impl NonMembershipAccumulator for GenericAccumulator<RsaGroup> {
    type NonMembershipProof = (BigInt, BigUint);

    fn non_mem_proof_create(&self, element: &Self::Element) -> Self::NonMembershipProof {
        GenericAccumulator::<RsaGroup>::non_mem_proof_create(self, element)
    }

    fn non_mem_ver(&self, proof: &Self::NonMembershipProof, element: &Self::Element) -> bool {
        GenericAccumulator::<RsaGroup>::non_mem_ver(self, proof, element)
    }
}

#[cfg(feature = "class-group")]
impl NonMembershipAccumulator for GenericAccumulator<ClassGroup> {
    type NonMembershipProof = (BigInt, ClassGroupElement);

    fn non_mem_proof_create(&self, element: &Self::Element) -> Self::NonMembershipProof {
        GenericAccumulator::<ClassGroup>::non_mem_proof_create_class(self, element)
    }

    fn non_mem_ver(&self, proof: &Self::NonMembershipProof, element: &Self::Element) -> bool {
        GenericAccumulator::<ClassGroup>::non_mem_ver_class(self, proof, element)
    }
}

impl<G> PrivatelyDelegatableAccumulator for GenericAccumulator<G>
where
    G: Group,
    G::Exponent: ToString,
{
    type BlindedMembershipProof = G::Element;
    type MembershipBlindingFactor = G::Exponent;
    type UpdatedBlindedMembershipProof = G::Element;
    type MembershipUpdateAux = G::Exponent;

    fn blind_mem_proof(
        &self,
        proof: &Self::MembershipProof,
    ) -> (Self::BlindedMembershipProof, Self::MembershipBlindingFactor) {
        GenericAccumulator::<G>::blind_mem_proof(self, proof)
    }

    fn blind_mem_proof_upd(
        &self,
        elem_in: Vec<Self::Element>,
        _elem_out: Vec<Self::Element>,
        acc_t: &<Self::Group as Group>::Element,
        blinded_proof: &Self::BlindedMembershipProof,
    ) -> (
        Self::UpdatedBlindedMembershipProof,
        Self::MembershipUpdateAux,
        <Self::Group as Group>::Element,
    ) {
        let delta = elem_in
            .iter()
            .cloned()
            .fold(G::exp_id(), |acc, x| G::exp_mul(&acc, &x));
        let upd = self.group.exp(blinded_proof, &delta);
        let _ = acc_t;
        (upd, delta, self.acc.clone())
    }

    fn ver_blind_mem_proof_upd(
        &self,
        acc_t: &<Self::Group as Group>::Element,
        blinded_proof: &Self::BlindedMembershipProof,
        upd_blinded_proof: &Self::UpdatedBlindedMembershipProof,
        aux: &Self::MembershipUpdateAux,
    ) -> bool {
        let expected_upd = self.group.exp(blinded_proof, aux);
        let expected_acc = self.group.exp(acc_t, aux);
        expected_upd == *upd_blinded_proof && expected_acc == self.acc
    }

    fn unblind_mem_proof(
        &self,
        blinded_proof: &Self::BlindedMembershipProof,
        st: &Self::MembershipBlindingFactor,
    ) -> Self::MembershipProof {
        GenericAccumulator::<G>::unblind_mem_proof(self, blinded_proof, st)
    }
}

impl PrivatelyDelegatableNonMembershipAccumulator for GenericAccumulator<RsaGroup> {
    type BlindedNonMembershipProof = (BigUint, BigUint);
    type UpdatedBlindedNonMembershipProof = (BigInt, BigUint);

    fn blind_non_mem_proof(&self, element: &Self::Element) -> Self::BlindedNonMembershipProof {
        GenericAccumulator::<RsaGroup>::blind_non_mem_proof(self, element)
    }

    fn blind_non_mem_proof_upd(
        &self,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
    ) -> Self::UpdatedBlindedNonMembershipProof {
        GenericAccumulator::<RsaGroup>::blind_non_mem_proof_upd(self, &blinded_non_mem_proof.0)
    }

    fn ver_blind_non_mem_proof_upd(
        &self,
        acc_t_prime: &<Self::Group as Group>::Element,
        blinded_non_mem_proof: &Self::BlindedNonMembershipProof,
        upd_blinded_non_mem_proof: &Self::UpdatedBlindedNonMembershipProof,
    ) -> bool {
        GenericAccumulator::<RsaGroup>::ver_blind_non_mem_proof_upd(
            self,
            acc_t_prime,
            &blinded_non_mem_proof.0,
            upd_blinded_non_mem_proof,
        )
    }

    fn unblind_non_mem_proof(
        &self,
        st: &<Self::Group as Group>::Exponent,
        upd_blinded_non_mem_proof: &Self::UpdatedBlindedNonMembershipProof,
    ) -> Self::NonMembershipProof {
        GenericAccumulator::<RsaGroup>::unblind_non_mem_proof(self, st, upd_blinded_non_mem_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn test_acc_add_del_no_change() {
        let mut acc = RsaAccumulator::setup();
        let initial_acc = acc.acc.clone();
        let element = BigUint::from_bytes_be(b"test_element");

        acc.add(&element);
        acc.del(&element);

        assert_eq!(
            acc.acc, initial_acc,
            "Accumulator value should be unchanged after add and remove of the same element"
        );
    }

    #[test]
    fn test_gen_mem_proof() {
        let mut acc = RsaAccumulator::setup();
        let element = BigUint::from(7usize);
        let ep = acc.add(&element);

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let proof = acc.mem_proof_create(&ep);

        assert!(acc.mem_ver(&proof, &ep));
    }

    #[test]
    fn test_non_mem_proof() {
        let mut acc = RsaAccumulator::setup();

        acc.add(&BigUint::from(2u32));
        acc.add(&BigUint::from(3u32));
        acc.add(&BigUint::from(7u32));

        let non_member = BigUint::from(5u32);

        let proof = acc.non_mem_proof_create(&non_member);
        assert!(
            acc.non_mem_ver(&proof, &non_member),
            "Non-membership proof should verify"
        );
    }

    #[test]
    fn test_blind_unblind_mem() {
        let mut acc = RsaAccumulator::setup();

        let element = BigUint::from(7usize);
        let ep: BigUint = acc.add(&element);

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let proof = acc.mem_proof_create(&ep);
        let blinded_proof = acc.blind_mem_proof(&proof);

        assert!(
            blinded_proof.0 != proof,
            "Proof is not blinded successfully"
        );

        let unblinded_proof = acc.unblind_mem_proof(&blinded_proof.0, &blinded_proof.1);
        assert!(
            unblinded_proof == proof,
            "Proof is not unblinded successfully"
        );
    }

    #[test]
    fn test_blind_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::setup();

        let ep = acc.add(&BigUint::from(200003u32));

        let acct = acc.acc.clone();

        let proof = acc.mem_proof_create(&ep);

        let blinded_proof = acc.blind_mem_proof(&proof);

        let elements_in = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

        let elements_out = vec![];
        for elem in &elements_in {
            acc.add(elem);
        }

        let upd_blind_proof =
            acc.blind_mem_proof_upd(elements_in, elements_out, &acct, &blinded_proof.0);

        assert!(acc.ver_blind_mem_proof_upd(
            &acct,
            &blinded_proof.0,
            &upd_blind_proof.0,
            &upd_blind_proof.1
        ));
    }

    #[test]
    fn test_blind_unblind_non_mem() {
        let mut acc = RsaAccumulator::setup();

        for i in 2..5 {
            acc.add(&BigUint::from(i as usize));
        }

        let non_member = BigUint::from(7usize);

        let blinded_proof = acc.blind_non_mem_proof(&non_member);

        for i in 10..12 {
            acc.add(&BigUint::from(i as usize));
        }

        let upd_blind_non_mem_proof = acc.blind_non_mem_proof_upd(&blinded_proof.0);

        let unblinded_proof = acc.unblind_non_mem_proof(&blinded_proof.1, &upd_blind_non_mem_proof);
        assert!(
            acc.non_mem_ver(&unblinded_proof, &non_member),
            "Non-membership proof should verify after unblinding"
        );
    }

    #[test]
    fn test_blind_non_mem_proof_upd_ver() {
        let mut acc = RsaAccumulator::setup();

        let non_member = BigUint::from(200003u32);

        let blinded_proof = acc.blind_non_mem_proof(&non_member);

        let elements_in = vec![
            BigUint::from(65537u32),
            BigUint::from(100003u32),
            BigUint::from(104729u32),
            BigUint::from(1299709u32),
            BigUint::from(15485863u32),
        ];

        for elem in &elements_in {
            acc.add(elem);
        }

        let acctprime = acc.acc.clone();

        let upd_blind_proof = acc.blind_non_mem_proof_upd(&blinded_proof.0);

        assert!(
            acc.ver_blind_non_mem_proof_upd(&acctprime, &blinded_proof.0, &upd_blind_proof),
            "Couldnt verify"
        );
    }
}
