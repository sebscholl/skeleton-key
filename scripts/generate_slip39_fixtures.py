#!/usr/bin/env python3

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, "/home/sebscholl/Code/slip-39-tools/lib/python3.12/site-packages")

from shamir_mnemonic import shamir


class DeterministicRandom:
    def __init__(self, seed: bytes):
        self.seed = seed
        self.counter = 0

    def __call__(self, length: int) -> bytes:
        output = b""
        while len(output) < length:
            counter_bytes = self.counter.to_bytes(8, "big")
            output += hashlib.sha256(self.seed + counter_bytes).digest()
            self.counter += 1
        return output[:length]


def flatten(groups):
    return [share for group in groups for share in group]


OUTPUT_PATH = Path(__file__).resolve().parent.parent / "spec" / "fixtures" / "recovery" / "slip39_golden_master.json"


def build_vectors():
    single_group_matrix = [
        (2, 4),
        (3, 4),
        (3, 5),
        (4, 5),
        (4, 6),
        (5, 6),
        (5, 7),
    ]

    vectors = []
    for offset, (threshold, count) in enumerate(single_group_matrix, start=1):
        master_secret = bytes(((offset * 17) + i) % 256 for i in range(16)).hex()
        passphrase = "" if (offset % 2 == 1) else f"PASS{offset}"
        vectors.append(
            {
                "name": f"single_group_{threshold}of{count}",
                "master_secret": master_secret,
                "passphrase": passphrase,
                "group_threshold": 1,
                "groups": [(threshold, count)],
                "extendable": bool(offset % 2),
                "iteration_exponent": offset % 3,
                "member_threshold": threshold,
                "member_count": count,
            }
        )

    multi_group_matrix = [
        {
            "name": "multi_group_2of3_groups_2of3_members",
            "group_threshold": 2,
            "groups": [(2, 3), (2, 3), (2, 3)],
        },
        {
            "name": "multi_group_2of3_groups_mixed_members",
            "group_threshold": 2,
            "groups": [(2, 3), (3, 5), (2, 4)],
        },
        {
            "name": "multi_group_3of5_groups_mixed_members",
            "group_threshold": 3,
            "groups": [(2, 3), (3, 4), (2, 5), (4, 5), (3, 5)],
        },
    ]

    for offset, config in enumerate(multi_group_matrix, start=(len(vectors) + 1)):
        master_secret = bytes(((offset * 17) + i) % 256 for i in range(16)).hex()
        passphrase = "" if (offset % 2 == 1) else f"PASS{offset}"
        vectors.append(
            {
                "name": config["name"],
                "master_secret": master_secret,
                "passphrase": passphrase,
                "group_threshold": config["group_threshold"],
                "groups": config["groups"],
                "extendable": bool(offset % 2),
                "iteration_exponent": offset % 3,
                "member_threshold": None,
                "member_count": None,
            }
        )

    return vectors


def main():
    rendered = {"vectors": []}
    for vector in build_vectors():
        random_seed = f"skeleton-key-slip39-{vector['name']}".encode("utf-8")
        shamir.RANDOM_BYTES = DeterministicRandom(random_seed)

        mnemonic_groups = shamir.generate_mnemonics(
            vector["group_threshold"],
            vector["groups"],
            bytes.fromhex(vector["master_secret"]),
            passphrase=vector["passphrase"].encode("ascii"),
            extendable=vector["extendable"],
            iteration_exponent=vector["iteration_exponent"],
        )

        recovery_group_count = vector["group_threshold"]
        selected_groups = mnemonic_groups[:recovery_group_count]
        recovery_set = []
        for group, (member_threshold, _member_count) in zip(selected_groups, vector["groups"]):
            recovery_set.extend(group[:member_threshold])

        insufficient_set = []
        insufficient_groups = mnemonic_groups[: max(recovery_group_count - 1, 1)]
        for group, (member_threshold, _member_count) in zip(insufficient_groups, vector["groups"]):
            if recovery_group_count == 1:
                insufficient_set.extend(group[: max(member_threshold - 1, 0)])
            else:
                insufficient_set.extend(group[:member_threshold])

        rendered["vectors"].append(
            {
                "name": vector["name"],
                "master_secret": vector["master_secret"],
                "passphrase": vector["passphrase"],
                "group_threshold": vector["group_threshold"],
                "member_threshold": vector["member_threshold"],
                "member_count": vector["member_count"],
                "groups": [
                    {"member_threshold": threshold, "member_count": count}
                    for threshold, count in vector["groups"]
                ],
                "random_seed": random_seed.decode("utf-8"),
                "extendable": vector["extendable"],
                "iteration_exponent": vector["iteration_exponent"],
                "mnemonic_groups": mnemonic_groups,
                "all_shares": flatten(mnemonic_groups),
                "recovery_set": recovery_set,
                "insufficient_recovery_set": insufficient_set,
            }
        )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(rendered, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
