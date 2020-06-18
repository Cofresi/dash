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
    std::vector<std::string> vstrHashes = { "0a92d6006f85a094c98c68106f253bfd079eba3f198c1fdc4a750a86be4454d4",
                                            "0c944fa8363a44a7723831e5c60e2b48f2de612f49fd000198aac6812cd26435",
                                            "c4988545c07ab0bc49e58ca2b2f47127457967265537715d9c060ef3c7e7f2d1",
                                            "b1d6a7eee744db02a5b1a40f07e7717ce0a272e6a59a480c7075213d14ad861b",
                                            "3aa9f34ec43877a75343d58439b3472951a46b1785267468d4c660820566932f",
                                            "e48e0a520a7a1bc6784146b6b3b47047046de05d3182deae5486c07f34f40ac8",
                                            "b4aa592da54031ab97bdb611261785501268c8ffc01b5f1e49769e4b3df7f222",
                                            "a0a6ecce3b4802a29e6a344e8c2617b5dc89d36cf9a6d35ba14639b008ed25ab",
                                            "4890771c8b900aa5117b089d13790be7d0cbca36adfa80070c232e06fd6c056a",
                                            "d52be90cd4d71debb5097c1fabdd6eeda5ee81dfc13d11d787bc47193ac31dad",
                                            "dcc3c15d8944a79b4c3996585e07044e123820f264da73327695c4f6c925d411",
                                            "7e9cdc74200f78b0955c5b5238e109455ba55d5bc47d6cf7b9f55bf5b22c3860",
                                            "a277d2f1a5c95c2f9f2cf0ea2a338eb9d471da9b48f9c3f033035809dad92c2c",
                                            "0838bea04e18b01fef76ca726654b60d973de5c93df318d340d4f97d37b13ac3",
                                            "39ce0497991519c63f4b91f11c849bcd9a9b40568873863c38d05acf549b6888",
                                            "192c43f39e9f8d18f743efa145e2a0eb9861667991e06c0d0636ae26634fde21",
                                            "c719e4178e2da52138b8b27b47f7c441ad4ddc39945257f0b57f19fbb17e1c28",
                                            "4c2c7a95aa9283ab0cf3cd5f495f4693013943cd3b8561a67c5b1a1b155700c2",
                                            "686dbebf13cbee4259b15fdaab2d0d5bfde36eecb17df1c3a7a045a33de7bf18",
                                            "4db3c2ec5232357b9b6579e4e39388cfcc03caffe81ded5ae2be95f27becd0ea",
                                            "2c852506e5c06100b03a881118eb7fc8ef34ee9cbd48cda2ba0d5673b85c0cf8",
                                            "1d2a88f34f6988e3cbf0ba11095647c5e3a503a89a4376e811eaa9c3c47e8119",
                                            "482b4a27e812499fc88e91b71ed25c0bf0133bfc172ee6806ebb1d9a4add6f30",
                                            "5deb9856962622aa65b840c70c3ccc15961825f10a342b407d6014b819aab13a",
                                            "381fbd47cd5ab01a48da6a20632b1cba9f4d3018d22c7131d99cd7b2a06295df"};

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
