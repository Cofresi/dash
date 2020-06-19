// Copyright (c) 2017-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/cbtx.h>
#include <evo/deterministicmns.h>
#include <llmq/quorums.h>
#include <llmq/quorums_blockprocessor.h>
#include <llmq/quorums_commitment.h>
#include <evo/simplifiedmns.h>
#include <evo/specialtx.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <univalue.h>
#include <validation.h>

bool CheckCbTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_COINBASE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cbtx-type");
    }

    if (!tx.IsCoinBase()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cbtx-invalid");
    }

    CCbTx cbTx;
    if (!GetTxPayload(tx, cbTx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cbtx-payload");
    }

    if (cbTx.nVersion == 0 || cbTx.nVersion > CCbTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cbtx-version");
    }

    if (pindexPrev && pindexPrev->nHeight + 1 != cbTx.nHeight) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cbtx-height");
    }

    if (pindexPrev) {
        bool fDIP0008Active = VersionBitsState(pindexPrev, Params().GetConsensus(), Consensus::DEPLOYMENT_DIP0008, versionbitscache) == ThresholdState::ACTIVE;
        if (fDIP0008Active && cbTx.nVersion < 2) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cbtx-version");
        }
    }

    return true;
}

// This can only be done after the block has been fully processed, as otherwise we won't have the finished MN list
bool CheckCbTxMerkleRoots(const CBlock& block, const CBlockIndex* pindex, CValidationState& state)
{
    if (block.vtx[0]->nType != TRANSACTION_COINBASE) {
        return true;
    }

    static int64_t nTimePayload = 0;
    static int64_t nTimeMerkleMNL = 0;
    static int64_t nTimeMerkleQuorum = 0;

    int64_t nTime1 = GetTimeMicros();

    CCbTx cbTx;
    if (!GetTxPayload(*block.vtx[0], cbTx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cbtx-payload");
    }

    int64_t nTime2 = GetTimeMicros(); nTimePayload += nTime2 - nTime1;
    LogPrint(BCLog::BENCHMARK, "          - GetTxPayload: %.2fms [%.2fs]\n", 0.001 * (nTime2 - nTime1), nTimePayload * 0.000001);

    if (pindex) {
        uint256 calculatedMerkleRoot;
        if (!CalcCbTxMerkleRootMNList(block, pindex->pprev, calculatedMerkleRoot, state)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cbtx-mnmerkleroot");
        }
        if (calculatedMerkleRoot != cbTx.merkleRootMNList) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cbtx-mnmerkleroot");
        }

        int64_t nTime3 = GetTimeMicros(); nTimeMerkleMNL += nTime3 - nTime2;
        LogPrint(BCLog::BENCHMARK, "          - CalcCbTxMerkleRootMNList: %.2fms [%.2fs]\n", 0.001 * (nTime3 - nTime2), nTimeMerkleMNL * 0.000001);

        if (cbTx.nVersion >= 2) {
            if (!CalcCbTxMerkleRootQuorums(block, pindex->pprev, calculatedMerkleRoot, state)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-cbtx-quorummerkleroot");
            }
            if (calculatedMerkleRoot != cbTx.merkleRootQuorums) {
                return state.DoS(100, false, REJECT_INVALID, "bad-cbtx-quorummerkleroot");
            }
        }

        int64_t nTime4 = GetTimeMicros(); nTimeMerkleQuorum += nTime4 - nTime3;
        LogPrint(BCLog::BENCHMARK, "          - CalcCbTxMerkleRootQuorums: %.2fms [%.2fs]\n", 0.001 * (nTime4 - nTime3), nTimeMerkleQuorum * 0.000001);

    }

    return true;
}

bool CalcCbTxMerkleRootMNList(const CBlock& block, const CBlockIndex* pindexPrev, uint256& merkleRootRet, CValidationState& state)
{
    LOCK(deterministicMNManager->cs);

    static int64_t nTimeDMN = 0;
    static int64_t nTimeSMNL = 0;
    static int64_t nTimeMerkle = 0;

    int64_t nTime1 = GetTimeMicros();

    try {
        CDeterministicMNList tmpMNList;
        if (!deterministicMNManager->BuildNewListFromBlock(block, pindexPrev, state, tmpMNList, false)) {
            return false;
        }

        int64_t nTime2 = GetTimeMicros(); nTimeDMN += nTime2 - nTime1;
        LogPrint(BCLog::BENCHMARK, "            - BuildNewListFromBlock: %.2fms [%.2fs]\n", 0.001 * (nTime2 - nTime1), nTimeDMN * 0.000001);

        CSimplifiedMNList sml(tmpMNList);

        int64_t nTime3 = GetTimeMicros(); nTimeSMNL += nTime3 - nTime2;
        LogPrint(BCLog::BENCHMARK, "            - CSimplifiedMNList: %.2fms [%.2fs]\n", 0.001 * (nTime3 - nTime2), nTimeSMNL * 0.000001);

        static CSimplifiedMNList smlCached;
        static uint256 merkleRootCached;
        static bool mutatedCached{false};

        if (sml.mnList == smlCached.mnList) {
            merkleRootRet = merkleRootCached;
            return !mutatedCached;
        }

        bool mutated = false;
        merkleRootRet = sml.CalcMerkleRoot(&mutated);

        int64_t nTime4 = GetTimeMicros(); nTimeMerkle += nTime4 - nTime3;
        LogPrint(BCLog::BENCHMARK, "            - CalcMerkleRoot: %.2fms [%.2fs]\n", 0.001 * (nTime4 - nTime3), nTimeMerkle * 0.000001);

        smlCached = std::move(sml);
        merkleRootCached = merkleRootRet;
        mutatedCached = mutated;

        return !mutated;
    } catch (const std::exception& e) {
        LogPrintf("%s -- failed: %s\n", __func__, e.what());
        return state.DoS(100, false, REJECT_INVALID, "failed-calc-cb-mnmerkleroot");
    }
}

bool CalcCbTxMerkleRootQuorums(const CBlock& block, const CBlockIndex* pindexPrev, uint256& merkleRootRet, CValidationState& state)
{
    static int64_t nTimeMinedAndActive = 0;
    static int64_t nTimeMined = 0;
    static int64_t nTimeLoop = 0;
    static int64_t nTimeMerkle = 0;

    int64_t nTime1 = GetTimeMicros();

    static std::map<Consensus::LLMQType, std::vector<const CBlockIndex*>> quorumsCached;
    static std::map<Consensus::LLMQType, std::vector<uint256>> qcHashesCached;

    // The returned quorums are in reversed order, so the most recent one is at index 0
    auto quorums = llmq::quorumBlockProcessor->GetMinedAndActiveCommitmentsUntilBlock(pindexPrev);
    std::map<Consensus::LLMQType, std::vector<uint256>> qcHashes;
    size_t hashCount = 0;

    int64_t nTime2 = GetTimeMicros(); nTimeMinedAndActive += nTime2 - nTime1;
    LogPrint(BCLog::BENCHMARK, "            - GetMinedAndActiveCommitmentsUntilBlock: %.2fms [%.2fs]\n", 0.001 * (nTime2 - nTime1), nTimeMinedAndActive * 0.000001);

    if (quorums == quorumsCached) {
        qcHashes = qcHashesCached;
    } else {
        for (const auto& p : quorums) {
            auto& v = qcHashes[p.first];
            v.reserve(p.second.size());
            for (const auto& p2 : p.second) {
                llmq::CFinalCommitment qc;
                uint256 minedBlockHash;
                bool found = llmq::quorumBlockProcessor->GetMinedCommitment(p.first, p2->GetBlockHash(), qc, minedBlockHash);
                if (!found) return state.DoS(100, false, REJECT_INVALID, "commitment-not-found");
                v.emplace_back(::SerializeHash(qc));
                hashCount++;
            }
        }
        quorumsCached = quorums;
        qcHashesCached = qcHashes;
    }

    int64_t nTime3 = GetTimeMicros(); nTimeMined += nTime3 - nTime2;
    LogPrint(BCLog::BENCHMARK, "            - GetMinedCommitment: %.2fms [%.2fs]\n", 0.001 * (nTime3 - nTime2), nTimeMined * 0.000001);

    // now add the commitments from the current block, which are not returned by GetMinedAndActiveCommitmentsUntilBlock
    // due to the use of pindexPrev (we don't have the tip index here)
    for (size_t i = 1; i < block.vtx.size(); i++) {
        auto& tx = block.vtx[i];

        if (tx->nVersion == 3 && tx->nType == TRANSACTION_QUORUM_COMMITMENT) {
            llmq::CFinalCommitmentTxPayload qc;
            if (!GetTxPayload(*tx, qc)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-qc-payload");
            }
            if (qc.commitment.IsNull()) {
                continue;
            }
            auto qcHash = ::SerializeHash(qc.commitment);
            const auto& params = Params().GetConsensus().llmqs.at((Consensus::LLMQType)qc.commitment.llmqType);
            auto& v = qcHashes[params.type];
            if (v.size() == params.signingActiveQuorumCount) {
                // we pop the last entry, which is actually the oldest quorum as GetMinedAndActiveCommitmentsUntilBlock
                // returned quorums in reversed order. This pop and later push can only work ONCE, but we rely on the
                // fact that a block can only contain a single commitment for one LLMQ type
                v.pop_back();
            }
            v.emplace_back(qcHash);
            hashCount++;
            if (v.size() > params.signingActiveQuorumCount) {
                return state.DoS(100, false, REJECT_INVALID, "excess-quorums");
            }
        }
    }

    std::vector<uint256> qcHashesVec;
    qcHashesVec.reserve(hashCount);

    for (const auto& p : qcHashes) {
        for (const auto& h : p.second) {
            qcHashesVec.emplace_back(h);
        }
    }

    for(int i=0; i < qcHashesVec.size(); i++){
        LogPrintf("unsorted hash -- %s\n", qcHashesVec[i].ToString());
    }

    std::sort(qcHashesVec.begin(), qcHashesVec.end());

    for(int i=0; i < qcHashesVec.size(); i++){
        LogPrintf("sorted hash -- %s\n", qcHashesVec[i].ToString());
    }

    // initialize hardcoded commitmenthash strings here and loop over them to fill hash vector

    std::vector<uint256> newHashesVec;
    newHashesVec.reserve(hashCount);
    std::vector<std::string> vstrHashes = {'d3d072de9f3b5aeb1292a0ff5f262c72e654a7796a7e2dc50359720e9b9ad5e8',
                                           '89a3713fb439a8ab324c6dfb9461342fb5c9098a0f2672568bf9f8721c9db19f',
                                           'eeeadf117f68a4745fbb3b24429d94eef436ba149b1a0161b92b3253e5692a5f',
                                           'b9200b64b587923f293847643b676db36ff31686218c330f215adf7bdeea5a2b',
                                           '1d47102f9ab7e343a26d4016222500d92ba5e310a05fc5c23749258c71c9dda9',
                                           'bf4f47afcf8f8bcfbdf9e50ab4ef38e9c8a56dc6a78c9c94824575fb8d14cad0',
                                           '5e324fba5902c89eab4be399cb698a9c7233d9db7fbcbc9211ee55ed7aad1da1',
                                           'acadcb634ff122844896e0e122bae52e54c7266328159bc34009f250424679be',
                                           'bb62d17067bfc214f7326289e1b46ec7196cec2b04fd46026bf7f752441b5d18',
                                           'fbb2a60f6f52a510523563694ac4a46c74808d44a27a600d26e8d628e112fe1a',
                                           'eba16b1ce8cff5ce0c5e80246c0ba7f5c92db60df871bfb54fd5506ed0e6c6e6',
                                           'ba67cf40324789515a63752849dd0dbb6f713315543b3e6886ef3fc358f31f66',
                                           'e88c34f8be569a8193833e911eef7703a0c9af9ff275a11df58391e1bfd1b9e2',
                                           '999c96380858215c9283993825bfbac65af9538f5802cdc8dafe17dd04a52781',
                                           'aecac7091d7d2e127bfb410f3d206809a52ec64119ffb01f93449b4732e881ee',
                                           'f8a5b55a6accc1a8c9325419843768dae0d86af452a8260931962cfc5a57dbea',
                                           'a4e9b00c65ca543cff4485529f6a7274a2a00bfc7e112f149a88665d24b65812',
                                           'a01493eafc021ba02137048c16fd0c72ee0c563a97d87870ed8f3fd6045cb08c',
                                           '397083d9b400237979480a3e1411f103f6af0d72aced44041ced3f53ab83e4fe',
                                           '4050338cf8c1f9286334640e11d727447458abb99579e01ee10d9aa4537d18b3',
                                           'dd3b21658ebbcb3fd0689bbdce4180ebc24f88e26e5142c1158232ec12a95e49',
                                           '2db206a524023d32b6550bf10d8f059bc3b74c932851ba4b637982d3e398fc25',
                                           '70aadd2dd4da1a836cc5f3b2171ca424afb1cef83e1e72bb46887cbf9948efbb',
                                           'ec58ed89a5b51c4194a517c619eed19293120ee2dadcbe4cc45bf13ffbd2d78d',
                                           '381fbd47cd5ab01a48da6a20632b1cba9f4d3018d22c7131d99cd7b2a06295df'};

    for(int i=0; i < vstrHashes.size(); i++){
        uint256 newHash;
        newHash.SetHex(vstrHashes[i]);
        newHashesVec.emplace_back(newHash);
    }

    for(int i=0; i < newHashesVec.size(); i++){
        LogPrintf("unsorted fixed hash -- %s\n", newHashesVec[i].ToString());
    }

    std::sort(newHashesVec.begin(), newHashesVec.end());

    for(int i=0; i < newHashesVec.size(); i++){
        LogPrintf("sorted fixed hash -- %s\n", newHashesVec[i].ToString());
    }

    int64_t nTime4 = GetTimeMicros(); nTimeLoop += nTime4 - nTime3;
    LogPrint(BCLog::BENCHMARK, "            - Loop: %.2fms [%.2fs]\n", 0.001 * (nTime4 - nTime3), nTimeLoop * 0.000001);

    bool mutated = false;
    merkleRootRet = ComputeMerkleRoot(qcHashesVec, &mutated);

    uint256 merkleRootFixed = ComputeMerkleRoot(newHashesVec, &mutated);
    LogPrintf("current merkleRootQuorums=%s\n", merkleRootRet.ToString());
    LogPrintf("fixed merkleRootQuorums=%s\n", merkleRootFixed.ToString());

    int64_t nTime5 = GetTimeMicros(); nTimeMerkle += nTime5 - nTime4;
    LogPrint(BCLog::BENCHMARK, "            - ComputeMerkleRoot: %.2fms [%.2fs]\n", 0.001 * (nTime5 - nTime4), nTimeMerkle * 0.000001);

    return !mutated;
}

std::string CCbTx::ToString() const
{
    return strprintf("CCbTx(nHeight=%d, nVersion=%d, merkleRootMNList=%s, merkleRootQuorums=%s)",
        nVersion, nHeight, merkleRootMNList.ToString(), merkleRootQuorums.ToString());
}
