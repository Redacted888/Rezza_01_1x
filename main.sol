// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title Rezza_01_1x — cross-venue reputation lattice with epoch-sealed witness rings
/// @author codename: cobalt drift / lattice nine
/// @notice Remix: compiler 0.8.28, optimizer 200 runs, deploy with zero args, then igniteLattice(true).

interface IERC20Minimal {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function allowance(address addressOwner, address spender) external view returns (uint256);
}

interface IRezzaWitnessSink {
    function onRezzaWitnessPulse(
        bytes32 zoneId,
        bytes32 imprint,
        address relayer,
        uint64 epoch,
        uint64 seq
    ) external;
}

library RezzaCodec {
    uint256 internal constant WORD_MASK = type(uint256).max;

    function packZoneMeta(uint32 tier, uint32 ttl, uint16 schema, bool live) internal pure returns (uint96) {
        uint96 packed = uint96(tier);
        packed |= uint96(ttl) << 32;
        packed |= uint96(schema) << 64;
        if (live) packed |= uint96(1) << 80;
        return packed;
    }

    function unpackTier(uint96 meta) internal pure returns (uint32) {
        return uint32(meta & WORD_MASK);
    }

    function unpackTtl(uint96 meta) internal pure returns (uint32) {
        return uint32((meta >> 32) & WORD_MASK);
    }

    function unpackSchema(uint96 meta) internal pure returns (uint16) {
        return uint16((meta >> 64) & 0xffff);
    }

    function unpackLive(uint96 meta) internal pure returns (bool) {
        return ((meta >> 80) & 1) == 1;
    }

    function zoneKey(string memory slug, uint32 tier) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("RZ1_ZONE", slug, tier));
    }

    function imprintDigest(
        bytes32 zoneId,
        bytes32 bodyHash,
        address author,
        uint64 epoch,
        uint64 seq,
        uint64 stampedAt
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(zoneId, bodyHash, author, epoch, seq, stampedAt));
    }

    function relayLeaf(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(left, right));
    }

    function clampU64(uint256 v, uint64 lo, uint64 hi) internal pure returns (uint64) {
        if (v < lo) return lo;
        if (v > hi) return hi;
        return uint64(v);
    }

    function clampU32(uint256 v, uint32 lo, uint32 hi) internal pure returns (uint32) {
        if (v < lo) return lo;
        if (v > hi) return hi;
        return uint32(v);
    }

    function saturatingSub(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a - b : 0;
    }
}

library RezzaMerkle {
    function verify(
        bytes32 leaf,
        bytes32[] memory proof,
        bytes32 root,
        uint256 index
    ) internal pure returns (bool) {
        bytes32 computed = leaf;
        uint256 ptr = proof.length;
        while (ptr > 0) {
            unchecked {
                ptr--;
            }
            bytes32 sibling = proof[ptr];
            if ((index & 1) == 0) {
                computed = keccak256(abi.encodePacked(computed, sibling));
            } else {
                computed = keccak256(abi.encodePacked(sibling, computed));
            }
            index >>= 1;
        }
        return computed == root;
    }

    function computeRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        uint256 len = leaves.length;
        if (len == 0) return bytes32(0);
        if (len == 1) return leaves[0];
        while (len > 1) {
            uint256 next = 0;
            for (uint256 i = 0; i < len; i += 2) {
                if (i + 1 < len) {
                    leaves[next] = keccak256(abi.encodePacked(leaves[i], leaves[i + 1]));
                } else {
                    leaves[next] = keccak256(abi.encodePacked(leaves[i], leaves[i]));
                }
                unchecked {
                    next++;
                }
            }
            len = next;
        }
        return leaves[0];
    }

    function emptyRoot() internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes32(0), bytes32(0)));
    }
}

library RezzaBitmap {
    function get(mapping(uint256 => uint256) storage map, uint256 index) internal view returns (bool) {
        uint256 bucket = index >> 8;
        uint256 bit = 1 << (index & 0xff);
        return (map[bucket] & bit) != 0;
    }

    function set(mapping(uint256 => uint256) storage map, uint256 index) internal {
        uint256 bucket = index >> 8;
        uint256 bit = 1 << (index & 0xff);
        map[bucket] |= bit;
    }

    function clear(mapping(uint256 => uint256) storage map, uint256 index) internal {
        uint256 bucket = index >> 8;
        uint256 bit = 1 << (index & 0xff);
        map[bucket] &= ~bit;
    }
}

library RezzaEIP712 {
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant RELAY_PERMIT_TYPEHASH =
        keccak256(
            "RezzaRelayPermit(bytes32 zoneId,bytes32 bodyHash,address relayer,uint64 epoch,uint64 seq,uint64 deadline)"
        );

    function domainSeparator(
        bytes32 nameHash,
        bytes32 versionHash,
