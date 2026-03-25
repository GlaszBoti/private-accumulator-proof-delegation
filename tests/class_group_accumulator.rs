#[cfg(all(feature = "rsa", feature = "class-group"))]
mod tests {
    use privacy_preserving_accumulators::groups::class_group::ClassGroup;
    use privacy_preserving_accumulators::traits::NonMembershipAccumulator;
    use privacy_preserving_accumulators::{GenericAccumulator, Group};

    fn setup_class_acc() -> GenericAccumulator<ClassGroup> {
        GenericAccumulator::new(ClassGroup::setup())
    }

    #[test]
    fn test_acc_add_del_no_change() {
        let mut acc = setup_class_acc();
        let initial_acc = acc.value().clone();
        acc.add(&"test_element");
        acc.del(&"test_element");
        assert_eq!(acc.value(), &initial_acc);
    }

    #[test]
    fn class_group_membership_proof_verifies() {
        let mut acc = setup_class_acc();

        let m1 = acc.add(&"alice");
        acc.add(&"bob");
        acc.add(&"carol");

        let proof = acc.mem_proof_create(&m1);
        assert!(acc.mem_ver(&proof, &m1));
    }

    #[test]
    fn test_blind_unblind_mem() {
        let mut acc = setup_class_acc();

        let member = acc.add(&"delta");
        acc.add(&"echo");

        let proof = acc.mem_proof_create(&member);
        let (blinded, blinder) = acc.blind_mem_proof(&proof);
        let unblinded = acc.unblind_mem_proof(&blinded, &blinder);

        assert_eq!(proof, unblinded);
        assert!(acc.mem_ver(&unblinded, &member));
    }

    #[test]
    fn test_non_mem_proof() {
        let mut acc = setup_class_acc();
        acc.add(&"alice");
        acc.add(&"bob");
        acc.add(&"carol");

        let non_member = acc.group.hash_to_prime(b"mallory");
        let proof = acc.non_mem_proof_create(&non_member);
        assert!(acc.non_mem_ver(&proof, &non_member));
    }

    #[test]
    #[ignore = "Blind membership proof update verification uses RSA-specific NIZK API"]
    fn test_blind_mem_proof_upd_ver() {}

    #[test]
    #[ignore = "Class-group blinded non-membership algorithms are not implemented"]
    fn test_blind_unblind_non_mem() {}

    #[test]
    #[ignore = "Class-group blinded non-membership update verification is not implemented"]
    fn test_blind_non_mem_proof_upd_ver() {}
}
