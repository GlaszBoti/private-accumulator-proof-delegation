use privacy_preserving_accumulators::Group;

#[cfg(all(feature = "rsa", feature = "class-group"))]
use privacy_preserving_accumulators::groups::class_group::ClassGroup;
#[cfg(feature = "rsa")]
use privacy_preserving_accumulators::groups::rsa_group::RsaGroup;

fn assert_group_properties<G: Group>(
    group: &G,
    a: G::Element,
    b: G::Element,
    c: G::Element,
    x: G::Exponent,
    y: G::Exponent,
) {
    let id = group.id();

    let left_assoc = group.mul(&group.mul(&a, &b), &c);
    let right_assoc = group.mul(&a, &group.mul(&b, &c));
    assert_eq!(
        left_assoc, right_assoc,
        "group operation must be associative"
    );

    assert_eq!(group.mul(&a, &id), a.clone(), "right identity must hold");
    assert_eq!(group.mul(&id, &a), a.clone(), "left identity must hold");

    let inv_a = group.inv(&a);
    assert_eq!(group.mul(&a, &inv_a), id.clone(), "right inverse must hold");
    assert_eq!(group.mul(&inv_a, &a), id, "left inverse must hold");

    let one = G::exp_id();
    assert_eq!(
        group.exp(&a, &one),
        a.clone(),
        "exponent identity must hold"
    );

    let xy = G::exp_mul(&x, &y);
    let lhs = group.exp(&group.exp(&a, &x), &y);
    let rhs = group.exp(&a, &xy);
    assert_eq!(lhs, rhs, "exponent composition must hold");
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_group_satisfies_group_properties() {
    let group = RsaGroup::setup();

    let x = group.hash_to_prime(b"x");
    let y = group.hash_to_prime(b"y");
    let z = group.hash_to_prime(b"z");

    let a = group.exp(&group.g(), &x);
    let b = group.exp(&group.g(), &y);
    let c = group.exp(&group.g(), &z);

    assert_group_properties(&group, a, b, c, x, y);
}

#[cfg(all(feature = "rsa", feature = "class-group"))]
#[test]
fn class_group_satisfies_group_properties() {
    let group = ClassGroup::setup();

    let x = group.hash_to_prime(b"x");
    let y = group.hash_to_prime(b"y");
    let z = group.hash_to_prime(b"z");

    let a = group.exp(&group.g(), &x);
    let b = group.exp(&group.g(), &y);
    let c = group.exp(&group.g(), &z);

    assert_group_properties(&group, a, b, c, x, y);
}
