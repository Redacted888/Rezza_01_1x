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
        uint256 chainId,
        address verifyingContract
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, nameHash, versionHash, chainId, verifyingContract));
    }

    function relayDigest(
        bytes32 domainSeparator_,
        bytes32 zoneId,
        bytes32 bodyHash,
        address relayer,
        uint64 epoch,
        uint64 seq,
        uint64 deadline
    ) internal pure returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(RELAY_PERMIT_TYPEHASH, zoneId, bodyHash, relayer, epoch, seq, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator_, structHash));
    }
}

contract Rezza_01_1x {
    using RezzaCodec for bytes32;
    using RezzaBitmap for mapping(uint256 => uint256);

    /* ------------------------------------------------------------------ *
     |  custom errors                                                     |
     * ------------------------------------------------------------------ */
    error RZ1_NotDirector();
    error RZ1_NotPendingDirector();
    error RZ1_NotWitness();
    error RZ1_NotCurator();
    error RZ1_NotRelayer();
    error RZ1_DirectorRenounced();
    error RZ1_LatticeFrozen();
    error RZ1_Reentry();
    error RZ1_ZeroAddress();
    error RZ1_ZeroBytes32();
    error RZ1_BadInput();
    error RZ1_ZoneExists();
    error RZ1_ZoneMissing();
    error RZ1_ZoneMuted();
    error RZ1_ZoneGap();
    error RZ1_SchemaExists();
    error RZ1_SchemaMissing();
    error RZ1_ImprintUsed();
    error RZ1_BatchTooLarge();
    error RZ1_BatchEmpty();
    error RZ1_BatchMismatch();
    error RZ1_SeqStale();
    error RZ1_PermitExpired();
    error RZ1_InvalidSignature();
    error RZ1_EpochDrift();
    error RZ1_RootStale();
    error RZ1_RootMissing();
    error RZ1_WitnessArmed();
    error RZ1_WitnessDisarmed();
    error RZ1_StakeLow();
    error RZ1_TreasuryLocked();
    error RZ1_NativeOnly();
    error RZ1_TransferFailed();
    error RZ1_TokenPullFailed();
    error RZ1_SinkReject();
    error RZ1_SameDirector();
    error RZ1_ClosureActive();
    error RZ1_ClosureMissing();
    error RZ1_ClosureFinalized();
    error RZ1_ClosureWindow();
    error RZ1_RingSaturated();
    error RZ1_Cooldown();

    /* ------------------------------------------------------------------ *
     |  events                                                            |
     * ------------------------------------------------------------------ */
    event RZ1_DirectorShifted(address indexed from, address indexed to);
    event RZ1_LatticeIgnited(bool live);
    event RZ1_FreezeToggled(bool frozen);
    event RZ1_WitnessArmed(address indexed witness, bool armed);
    event RZ1_CuratorArmed(address indexed curator, bool armed);
    event RZ1_RelayerArmed(address indexed relayer, bool armed);
    event RZ1_ZoneOpened(bytes32 indexed zoneId, string slug, uint32 tier, uint16 schema);
    event RZ1_ZoneMuted(bytes32 indexed zoneId, bool muted);
    event RZ1_SchemaRegistered(uint16 indexed schemaId, bytes32 schemaHash);
    event RZ1_EpochAdvanced(uint64 epoch, address indexed nudger);
    event RZ1_ImprintSealed(
        uint256 indexed slot,
        bytes32 zoneId,
        bytes32 imprint,
        bytes4 glyph,
        address witness,
        uint64 epoch
    );
    event RZ1_RelayAccepted(
        bytes32 indexed zoneId,
        bytes32 imprint,
        address indexed relayer,
        uint64 seq,
        address sink
    );
    event RZ1_RootAnchored(uint64 indexed epoch, bytes32 root, address indexed curator);
    event RZ1_ClosureOpened(bytes32 indexed closureId, bytes32 zoneId, uint64 unlockAt);
    event RZ1_ClosureFinalized(bytes32 indexed closureId, bytes32 imprint);
    event RZ1_StakeDeposited(address indexed witness, uint256 amount, uint256 total);
    event RZ1_StakeReleased(address indexed witness, uint256 amount, uint256 total);
    event RZ1_TreasurySweep(address indexed token, address indexed to, uint256 amount);
    event RZ1_NativeReceived(address indexed from, uint256 amount);

    /* ------------------------------------------------------------------ *
     |  constants + immutables                                            |
     * ------------------------------------------------------------------ */
    uint256 internal constant RING_DEPTH = 512;
    uint256 internal constant MAX_BATCH = 48;
    uint256 internal constant MIN_WITNESS_STAKE = 0.02 ether;
    uint256 internal constant MAX_WITNESS_STAKE = 12 ether;
    uint256 internal constant CLOSURE_LAG = 18;
    uint256 internal constant CLOSURE_TTL = 86400;
    uint256 internal constant RELAY_COOLDOWN = 4;
    uint256 internal constant SCHEMA_CAP = 256;
    uint256 internal constant ZONE_CAP = 1024;

    bytes32 internal constant RZ1_ORBIT_SEED =
        0x4e7a9c2f5b8d1e4a7c0f3b6e9a2d5c8f1b4e7a0c3f6b9d2e5a8c1f4b7e0d3a6;
    bytes32 internal constant RZ1_TIDAL_SEED =
        0x9b2e5a8c1f4b7e0d3a6f9c2d5b8e1a4c7f0b3e6a9d2f5c8b1e4a7c0f3b6e9a2d5;
    bytes32 internal constant RZ1_AURORA_SEED =
        0x1f8c3b6e9a2d5f8c1b4e7a0c3f6b9d2e5a8c1f4b7e0d3a6f9c2d5b8e1a4c7f0b3;

    address public immutable NORTH_RELAY_BOOT;
    address public immutable SOUTH_MIRROR_BOOT;
    address public immutable EAST_WITNESS_BOOT;
    address public immutable WEST_CUSTODY_BOOT;
    address public immutable FEE_SINK_BOOT;
    bytes32 public immutable LATTICE_IMPRINT;
    uint64 public immutable BORN_AT;

    bytes32 private immutable _NAME_HASH;
    bytes32 private immutable _VERSION_HASH;
    bytes32 private immutable _DOMAIN_SEPARATOR;

    /* ------------------------------------------------------------------ *
     |  storage structs                                                   |
     * ------------------------------------------------------------------ */
    struct ImprintCell {
        bytes32 imprint;
        bytes32 zoneId;
        bytes4 glyph;
        address witness;
        uint64 epoch;
        uint64 stamped;
    }

    struct ZoneLane {
        uint96 meta;
        uint64 lastSeq;
        uint64 openedAt;
        address sink;
        bool muted;
    }

    struct SchemaEntry {
        bytes32 schemaHash;
        bool live;
        uint64 registeredAt;
    }

    struct PendingClosure {
        bytes32 zoneId;
        bytes32 commit;
        uint64 unlockAt;
        uint64 loggedAt;
        bool finalized;
    }

    struct EpochRoot {
        bytes32 root;
        uint64 anchoredAt;
        address curator;
        bool set;
    }

    /* ------------------------------------------------------------------ *
     |  state                                                             |
     * ------------------------------------------------------------------ */
    address public director;
    address public pendingDirector;
    bool public directorRenounced;
    bool public latticeLive;
    bool public frozen;
    uint64 public epoch;
    uint256 public ringHead;
    uint256 public liveImprints;
    uint256 private _gate;

    mapping(address => bool) public witnessArmed;
    mapping(address => bool) public curatorArmed;
    mapping(address => bool) public relayerArmed;
    mapping(address => uint256) public witnessStake;
    mapping(address => uint256) public witnessNonce;
    mapping(address => uint256) public relayerNonce;
    mapping(address => uint256) public lastRelayBlock;

    mapping(bytes32 => ZoneLane) public zones;
    mapping(bytes32 => bool) public zoneRegistered;
    mapping(uint16 => SchemaEntry) public schemas;
    mapping(uint16 => bool) public schemaRegistered;
    mapping(bytes32 => bool) public imprintConsumed;
    mapping(bytes32 => PendingClosure) public closures;
    mapping(uint64 => EpochRoot) public epochRoots;
    mapping(uint256 => ImprintCell) public ring;
    mapping(uint256 => uint256) public relayBitmap;

    uint256 public zoneCount;
    uint256 public schemaCount;
    uint256 public closureCount;
    uint256 public treasuryLockUntil;

    /* ------------------------------------------------------------------ *
     |  modifiers                                                         |
     * ------------------------------------------------------------------ */
    modifier onlyDirector() {
        if (directorRenounced) revert RZ1_DirectorRenounced();
        if (msg.sender != director) revert RZ1_NotDirector();
        _;
    }

    modifier whenLatticeLive() {
        if (!latticeLive) revert RZ1_BadInput();
        _;
    }

    modifier whenNotFrozen() {
        if (frozen) revert RZ1_LatticeFrozen();
        _;
    }

    modifier nonReentrant() {
        if (_gate != 0) revert RZ1_Reentry();
        _gate = 1;
        _;
        _gate = 0;
    }

    /* ------------------------------------------------------------------ *
     |  constructor                                                       |
     * ------------------------------------------------------------------ */
    constructor() {
        director = msg.sender;
        NORTH_RELAY_BOOT = 0x4bE8f2A7c1D9e6B3a0F5d8C2e7B1a4F9c6E0d3B7;
        SOUTH_MIRROR_BOOT = 0x9a3C7e1F4b8D2a6E0c5B9f3A7d1E4c8B2f6A0d5E;
        EAST_WITNESS_BOOT = 0xF6d2A9c4E7b1D8f0A3e6C9b2F5a8D1e4C7b0F3a6;
        WEST_CUSTODY_BOOT = 0x2e7B4a9C1f6D3e8A0c5F2b7E4d9A1c6F3b8E0a5;
        FEE_SINK_BOOT = 0x8D1f4a7C0e3B6A9d2F5c8E1b4A7d0C3e6F9b2A5;
        LATTICE_IMPRINT = keccak256(
            abi.encodePacked(RZ1_ORBIT_SEED, RZ1_TIDAL_SEED, NORTH_RELAY_BOOT, msg.sender, block.timestamp)
        );
        BORN_AT = uint64(block.timestamp);
        _NAME_HASH = keccak256(bytes("Rezza_01_1x"));
        _VERSION_HASH = keccak256(bytes("1"));
        _DOMAIN_SEPARATOR = RezzaEIP712.domainSeparator(_NAME_HASH, _VERSION_HASH, block.chainid, address(this));
        witnessArmed[EAST_WITNESS_BOOT] = true;
        curatorArmed[NORTH_RELAY_BOOT] = true;
        relayerArmed[SOUTH_MIRROR_BOOT] = true;
        epochRoots[0] = EpochRoot({
            root: RezzaMerkle.emptyRoot(),
            anchoredAt: BORN_AT,
            curator: NORTH_RELAY_BOOT,
            set: true
        });
    }

    /* ------------------------------------------------------------------ *
     |  receive                                                           |
     * ------------------------------------------------------------------ */
    receive() external payable {
        emit RZ1_NativeReceived(msg.sender, msg.value);
    }

    /* ------------------------------------------------------------------ *
     |  director controls                                                 |
     * ------------------------------------------------------------------ */
    function transferDirector(address next) external onlyDirector {
        if (next == address(0)) revert RZ1_ZeroAddress();
        if (next == director) revert RZ1_SameDirector();
        pendingDirector = next;
    }

    function acceptDirector() external {
        if (pendingDirector == address(0)) revert RZ1_NotPendingDirector();
        if (msg.sender != pendingDirector) revert RZ1_NotPendingDirector();
        address prev = director;
        director = pendingDirector;
        pendingDirector = address(0);
        emit RZ1_DirectorShifted(prev, director);
    }

    function renounceDirector() external onlyDirector {
        directorRenounced = true;
        director = address(0);
        pendingDirector = address(0);
        emit RZ1_DirectorShifted(msg.sender, address(0));
    }

    function igniteLattice(bool live) external onlyDirector {
        latticeLive = live;
        emit RZ1_LatticeIgnited(live);
    }

    function setFrozen(bool on) external onlyDirector {
        frozen = on;
        emit RZ1_FreezeToggled(on);
    }

    function armWitness(address witness, bool armed) external onlyDirector {
        if (witness == address(0)) revert RZ1_ZeroAddress();
        witnessArmed[witness] = armed;
        emit RZ1_WitnessArmed(witness, armed);
    }

    function armCurator(address curator, bool armed) external onlyDirector {
        if (curator == address(0)) revert RZ1_ZeroAddress();
        curatorArmed[curator] = armed;
        emit RZ1_CuratorArmed(curator, armed);
    }

    function armRelayer(address relayer, bool armed) external onlyDirector {
        if (relayer == address(0)) revert RZ1_ZeroAddress();
        relayerArmed[relayer] = armed;
        emit RZ1_RelayerArmed(relayer, armed);
    }

    function lockTreasury(uint256 until) external onlyDirector {
        treasuryLockUntil = until;
    }

    /* ------------------------------------------------------------------ *
     |  schema + zone administration                                      |
     * ------------------------------------------------------------------ */
    function registerSchema(uint16 schemaId, bytes32 schemaHash) external onlyDirector {
        if (schemaHash == bytes32(0)) revert RZ1_ZeroBytes32();
        if (schemaRegistered[schemaId]) revert RZ1_SchemaExists();
        if (schemaCount >= SCHEMA_CAP) revert RZ1_BadInput();
        schemas[schemaId] = SchemaEntry({schemaHash: schemaHash, live: true, registeredAt: uint64(block.timestamp)});
        schemaRegistered[schemaId] = true;
        unchecked {
            schemaCount++;
        }
        emit RZ1_SchemaRegistered(schemaId, schemaHash);
    }

    function muteSchema(uint16 schemaId, bool live) external onlyDirector {
        if (!schemaRegistered[schemaId]) revert RZ1_SchemaMissing();
        schemas[schemaId].live = live;
    }

    function openZone(
        string calldata slug,
        uint32 tier,
        uint16 schemaId,
        uint32 ttl,
        address sink
    ) external onlyDirector returns (bytes32 zoneId) {
        if (bytes(slug).length == 0 || bytes(slug).length > 64) revert RZ1_BadInput();
        if (!schemaRegistered[schemaId]) revert RZ1_SchemaMissing();
        if (!schemas[schemaId].live) revert RZ1_SchemaMissing();
        if (zoneCount >= ZONE_CAP) revert RZ1_BadInput();
        zoneId = RezzaCodec.zoneKey(slug, tier);
        if (zoneRegistered[zoneId]) revert RZ1_ZoneExists();
        zones[zoneId] = ZoneLane({
            meta: RezzaCodec.packZoneMeta(tier, ttl, schemaId, true),
            lastSeq: 0,
            openedAt: uint64(block.timestamp),
            sink: sink,
            muted: false
        });
        zoneRegistered[zoneId] = true;
        unchecked {
            zoneCount++;
        }
        emit RZ1_ZoneOpened(zoneId, slug, tier, schemaId);
    }

    function muteZone(bytes32 zoneId, bool muted) external onlyDirector {
        if (!zoneRegistered[zoneId]) revert RZ1_ZoneMissing();
        zones[zoneId].muted = muted;
        emit RZ1_ZoneMuted(zoneId, muted);
    }

    function retargetZoneSink(bytes32 zoneId, address sink) external onlyDirector {
        if (!zoneRegistered[zoneId]) revert RZ1_ZoneMissing();
        zones[zoneId].sink = sink;
    }
