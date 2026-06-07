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

    /* ------------------------------------------------------------------ *
     |  epoch + merkle roots                                              |
     * ------------------------------------------------------------------ */
    function nudgeEpoch() external whenLatticeLive whenNotFrozen {
        if (!curatorArmed[msg.sender] && msg.sender != director) revert RZ1_NotCurator();
        unchecked {
            epoch++;
        }
        emit RZ1_EpochAdvanced(epoch, msg.sender);
    }

    function anchorEpochRoot(bytes32 root) external whenLatticeLive whenNotFrozen {
        if (!curatorArmed[msg.sender] && msg.sender != director) revert RZ1_NotCurator();
        if (root == bytes32(0)) revert RZ1_ZeroBytes32();
        EpochRoot storage slot = epochRoots[epoch];
        if (slot.set && slot.root == root) revert RZ1_BadInput();
        slot.root = root;
        slot.anchoredAt = uint64(block.timestamp);
        slot.curator = msg.sender;
        slot.set = true;
        emit RZ1_RootAnchored(epoch, root, msg.sender);
    }

    function anchorEpochRootFromLeaves(bytes32[] calldata leaves) external whenLatticeLive whenNotFrozen {
        if (!curatorArmed[msg.sender] && msg.sender != director) revert RZ1_NotCurator();
        if (leaves.length == 0) revert RZ1_BatchEmpty();
        if (leaves.length > MAX_BATCH) revert RZ1_BatchTooLarge();
        bytes32[] memory buf = new bytes32[](leaves.length);
        for (uint256 i = 0; i < leaves.length; ) {
            if (leaves[i] == bytes32(0)) revert RZ1_ZeroBytes32();
            buf[i] = leaves[i];
            unchecked {
                i++;
            }
        }
        bytes32 root = RezzaMerkle.computeRoot(buf);
        EpochRoot storage slot = epochRoots[epoch];
        slot.root = root;
        slot.anchoredAt = uint64(block.timestamp);
        slot.curator = msg.sender;
        slot.set = true;
        emit RZ1_RootAnchored(epoch, root, msg.sender);
    }

    /* ------------------------------------------------------------------ *
     |  witness stake                                                     |
     * ------------------------------------------------------------------ */
    function depositWitnessStake() external payable whenLatticeLive whenNotFrozen nonReentrant {
        if (!witnessArmed[msg.sender]) revert RZ1_NotWitness();
        if (msg.value == 0) revert RZ1_BadInput();
        uint256 next = witnessStake[msg.sender] + msg.value;
        if (next > MAX_WITNESS_STAKE) revert RZ1_BadInput();
        witnessStake[msg.sender] = next;
        emit RZ1_StakeDeposited(msg.sender, msg.value, next);
    }

    function releaseWitnessStake(uint256 amount) external nonReentrant {
        if (!witnessArmed[msg.sender] && msg.sender != director) revert RZ1_NotWitness();
        if (amount == 0) revert RZ1_BadInput();
        uint256 held = witnessStake[msg.sender];
        if (held < amount) revert RZ1_StakeLow();
        if (held - amount < MIN_WITNESS_STAKE && msg.sender != director) revert RZ1_StakeLow();
        witnessStake[msg.sender] = held - amount;
        _sendNative(msg.sender, amount);
        emit RZ1_StakeReleased(msg.sender, amount, witnessStake[msg.sender]);
    }

    /* ------------------------------------------------------------------ *
     |  imprint sealing                                                   |
     * ------------------------------------------------------------------ */
    function sealImprint(
        bytes32 zoneId,
        bytes32 bodyHash,
        bytes4 glyph,
        uint64 seq
    ) external whenLatticeLive whenNotFrozen nonReentrant returns (bytes32 imprint) {
        if (!witnessArmed[msg.sender]) revert RZ1_NotWitness();
        if (!zoneRegistered[zoneId]) revert RZ1_ZoneMissing();
        ZoneLane storage lane = zones[zoneId];
        if (lane.muted) revert RZ1_ZoneMuted();
        if (bodyHash == bytes32(0)) revert RZ1_ZeroBytes32();
        if (witnessStake[msg.sender] < MIN_WITNESS_STAKE) revert RZ1_StakeLow();
        if (seq != lane.lastSeq + 1) revert RZ1_ZoneGap();
        imprint = RezzaCodec.imprintDigest(zoneId, bodyHash, msg.sender, epoch, seq, uint64(block.timestamp));
        if (imprintConsumed[imprint]) revert RZ1_ImprintUsed();
        imprintConsumed[imprint] = true;
        lane.lastSeq = seq;
        uint256 slot = ringHead % RING_DEPTH;
        ring[slot] = ImprintCell({
            imprint: imprint,
            zoneId: zoneId,
            glyph: glyph,
            witness: msg.sender,
            epoch: epoch,
            stamped: uint64(block.timestamp)
        });
        unchecked {
            ringHead++;
            liveImprints++;
        }
        emit RZ1_ImprintSealed(slot, zoneId, imprint, glyph, msg.sender, epoch);
    }

    function sealImprintBatch(
        bytes32 zoneId,
        bytes32[] calldata bodyHashes,
        bytes4[] calldata glyphs
    ) external whenLatticeLive whenNotFrozen nonReentrant returns (bytes32[] memory imprints) {
        if (!witnessArmed[msg.sender]) revert RZ1_NotWitness();
        if (!zoneRegistered[zoneId]) revert RZ1_ZoneMissing();
        if (bodyHashes.length == 0) revert RZ1_BatchEmpty();
        if (bodyHashes.length > MAX_BATCH) revert RZ1_BatchTooLarge();
        if (bodyHashes.length != glyphs.length) revert RZ1_BatchMismatch();
        if (witnessStake[msg.sender] < MIN_WITNESS_STAKE) revert RZ1_StakeLow();
        ZoneLane storage lane = zones[zoneId];
        if (lane.muted) revert RZ1_ZoneMuted();
        imprints = new bytes32[](bodyHashes.length);
        uint64 seq = lane.lastSeq;
        for (uint256 i = 0; i < bodyHashes.length; ) {
            if (bodyHashes[i] == bytes32(0)) revert RZ1_ZeroBytes32();
            unchecked {
                seq++;
            }
            bytes32 imprint = RezzaCodec.imprintDigest(
                zoneId,
                bodyHashes[i],
                msg.sender,
                epoch,
                seq,
                uint64(block.timestamp)
            );
            if (imprintConsumed[imprint]) revert RZ1_ImprintUsed();
            imprintConsumed[imprint] = true;
            imprints[i] = imprint;
            uint256 slot = ringHead % RING_DEPTH;
            ring[slot] = ImprintCell({
                imprint: imprint,
                zoneId: zoneId,
                glyph: glyphs[i],
                witness: msg.sender,
                epoch: epoch,
                stamped: uint64(block.timestamp)
            });
            unchecked {
                ringHead++;
                liveImprints++;
            }
            emit RZ1_ImprintSealed(slot, zoneId, imprint, glyphs[i], msg.sender, epoch);
            unchecked {
                i++;
            }
        }
        lane.lastSeq = seq;
    }

    /* ------------------------------------------------------------------ *
     |  relay + sink delivery                                             |
     * ------------------------------------------------------------------ */
    function relayImprint(
        bytes32 zoneId,
        bytes32 bodyHash,
        uint64 seq
    ) external whenLatticeLive whenNotFrozen nonReentrant returns (bytes32 imprint) {
        if (!relayerArmed[msg.sender]) revert RZ1_NotRelayer();
        if (!zoneRegistered[zoneId]) revert RZ1_ZoneMissing();
        ZoneLane storage lane = zones[zoneId];
        if (lane.muted) revert RZ1_ZoneMuted();
        if (bodyHash == bytes32(0)) revert RZ1_ZeroBytes32();
        if (block.number < lastRelayBlock[msg.sender] + RELAY_COOLDOWN) revert RZ1_Cooldown();
        if (seq <= lane.lastSeq) revert RZ1_SeqStale();
        imprint = RezzaCodec.imprintDigest(zoneId, bodyHash, msg.sender, epoch, seq, uint64(block.timestamp));
        if (imprintConsumed[imprint]) revert RZ1_ImprintUsed();
        imprintConsumed[imprint] = true;
        lane.lastSeq = seq;
        lastRelayBlock[msg.sender] = block.number;
        unchecked {
            relayerNonce[msg.sender]++;
        }
        address sink = lane.sink;
        if (sink != address(0)) {
            _deliverToSink(sink, zoneId, imprint, msg.sender, seq);
        }
        emit RZ1_RelayAccepted(zoneId, imprint, msg.sender, seq, sink);
    }

    function relayWithPermit(
        bytes32 zoneId,
        bytes32 bodyHash,
        uint64 seq,
        uint64 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenLatticeLive whenNotFrozen nonReentrant returns (bytes32 imprint) {
        if (!zoneRegistered[zoneId]) revert RZ1_ZoneMissing();
        if (block.timestamp > deadline) revert RZ1_PermitExpired();
        address signer = _recoverRelaySigner(zoneId, bodyHash, msg.sender, seq, deadline, v, r, s);
        if (!relayerArmed[signer]) revert RZ1_NotRelayer();
        ZoneLane storage lane = zones[zoneId];
        if (lane.muted) revert RZ1_ZoneMuted();
        if (bodyHash == bytes32(0)) revert RZ1_ZeroBytes32();
        if (seq <= lane.lastSeq) revert RZ1_SeqStale();
        imprint = RezzaCodec.imprintDigest(zoneId, bodyHash, signer, epoch, seq, uint64(block.timestamp));
        if (imprintConsumed[imprint]) revert RZ1_ImprintUsed();
        imprintConsumed[imprint] = true;
        lane.lastSeq = seq;
        unchecked {
            relayerNonce[signer]++;
        }
        address sink = lane.sink;
        if (sink != address(0)) {
            _deliverToSink(sink, zoneId, imprint, signer, seq);
        }
        emit RZ1_RelayAccepted(zoneId, imprint, signer, seq, sink);
    }

    /* ------------------------------------------------------------------ *
     |  closure commits                                                   |
     * ------------------------------------------------------------------ */
    function logClosure(bytes32 zoneId, bytes32 commit) external whenLatticeLive whenNotFrozen {
        if (!zoneRegistered[zoneId]) revert RZ1_ZoneMissing();
        if (commit == bytes32(0)) revert RZ1_ZeroBytes32();
        bytes32 closureId = keccak256(abi.encodePacked(RZ1_AURORA_SEED, zoneId, commit, msg.sender));
        if (closures[closureId].loggedAt != 0) revert RZ1_ClosureActive();
        uint64 unlockAt = uint64(block.timestamp + CLOSURE_LAG);
        closures[closureId] = PendingClosure({
            zoneId: zoneId,
            commit: commit,
            unlockAt: unlockAt,
            loggedAt: uint64(block.timestamp),
            finalized: false
        });
        unchecked {
            closureCount++;
        }
        emit RZ1_ClosureOpened(closureId, zoneId, unlockAt);
    }

    function finalizeClosure(bytes32 closureId, bytes32 bodyHash, bytes4 glyph) external whenLatticeLive whenNotFrozen {
        PendingClosure storage pending = closures[closureId];
        if (pending.loggedAt == 0) revert RZ1_ClosureMissing();
        if (pending.finalized) revert RZ1_ClosureFinalized();
        if (block.timestamp < pending.unlockAt) revert RZ1_ClosureWindow();
        if (block.timestamp > pending.loggedAt + CLOSURE_TTL) revert RZ1_ClosureWindow();
        bytes32 revealed = keccak256(abi.encodePacked(bodyHash, glyph, msg.sender));
        if (revealed != pending.commit) revert RZ1_BadInput();
        bytes32 imprint = keccak256(abi.encodePacked(pending.zoneId, revealed, closureId));
        imprintConsumed[imprint] = true;
        pending.finalized = true;
        emit RZ1_ClosureFinalized(closureId, imprint);
    }

    /* ------------------------------------------------------------------ *
     |  treasury                                                          |
     * ------------------------------------------------------------------ */
    function sweepNativeTreasury(address to, uint256 amount) external onlyDirector nonReentrant {
        if (block.timestamp < treasuryLockUntil) revert RZ1_TreasuryLocked();
        if (to == address(0)) revert RZ1_ZeroAddress();
        _sendNative(to, amount);
        emit RZ1_TreasurySweep(address(0), to, amount);
    }

    function sweepTokenTreasury(address token, address to, uint256 amount) external onlyDirector nonReentrant {
        if (block.timestamp < treasuryLockUntil) revert RZ1_TreasuryLocked();
        if (token == address(0) || to == address(0)) revert RZ1_ZeroAddress();
        bool ok = IERC20Minimal(token).transfer(to, amount);
        if (!ok) revert RZ1_TokenPullFailed();
        emit RZ1_TreasurySweep(token, to, amount);
    }

    /* ------------------------------------------------------------------ *
     |  verification views                                                |
     * ------------------------------------------------------------------ */
    function verifyImprintInRoot(
        bytes32 zoneId,
        bytes32 bodyHash,
        address author,
        uint64 epoch_,
        uint64 seq,
        uint64 stampedAt,
        bytes32[] calldata proof,
        uint256 index,
        uint64 epochLookup
    ) external view returns (bool) {
        bytes32 leaf = RezzaCodec.imprintDigest(zoneId, bodyHash, author, epoch_, seq, stampedAt);
        EpochRoot storage slot = epochRoots[epochLookup];
        if (!slot.set) revert RZ1_RootMissing();
        return RezzaMerkle.verify(leaf, proof, slot.root, index);
    }

    function domainSeparator() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }

    function zoneMeta(bytes32 zoneId) external view returns (uint32 tier, uint32 ttl, uint16 schema, bool live) {
        if (!zoneRegistered[zoneId]) revert RZ1_ZoneMissing();
        uint96 meta = zones[zoneId].meta;
        tier = RezzaCodec.unpackTier(meta);
        ttl = RezzaCodec.unpackTtl(meta);
        schema = RezzaCodec.unpackSchema(meta);
        live = RezzaCodec.unpackLive(meta);
    }

    function ringCell(uint256 absoluteSlot) external view returns (ImprintCell memory cell) {
        if (absoluteSlot >= ringHead) revert RZ1_BadInput();
        cell = ring[absoluteSlot % RING_DEPTH];
    }

    function recentRingWindow(uint256 count) external view returns (ImprintCell[] memory cells) {
        if (count > RING_DEPTH) revert RZ1_BadInput();
        if (ringHead == 0) {
            return new ImprintCell[](0);
        }
        uint256 available = ringHead < RING_DEPTH ? ringHead : RING_DEPTH;
        if (count > available) count = available;
        cells = new ImprintCell[](count);
        uint256 start = ringHead - count;
        for (uint256 i = 0; i < count; ) {
            cells[i] = ring[(start + i) % RING_DEPTH];
            unchecked {
                i++;
            }
        }
    }

    function latticeFingerprint() external view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                LATTICE_IMPRINT,
                epoch,
                ringHead,
                liveImprints,
                zoneCount,
                schemaCount,
                latticeLive,
