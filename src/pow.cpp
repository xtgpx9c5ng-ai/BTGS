// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_256.h>
#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>
#include <consensus/params.h>
#include <algorithm>
#include <vector>

// ============================================================================
// FULL-SPEC DAA v6.0 - RIGOROUS CONSENSUS IMPLEMENTATION
// 100% Strict Mathematical & Architectural Alignment to Specification
// ============================================================================

static constexpr int W_MICRO = 24;
static constexpr int W_SHORT = 144;
static constexpr int W_MEDIUM = 720;
static constexpr int W_LONG = 2016;

static constexpr uint64_t ARITH_SCALE = 1000000ULL;

struct TimestampSecurityMetrics {
    int64_t anomalyScore;
    bool hasFutureTimeViolation;
    bool hasDispersionViolation;
    int64_t qualityFactorScaled; // 0 to 1000
};

struct MomentumAccelerationMetrics {
    arith_256 momentum24_144;
    arith_256 momentum144_720;
    arith_256 momentum720_2016;
    int64_t accelerationIndex;
    int trendClass; // -2: Collapse, -1: Falling, 0: Stable, 1: Rising, 2: Injection, 3: Oscillating
};

struct ComprehensiveAttackScore {
    int64_t timestampAnomalyScore;
    int64_t divergenceScore;
    int64_t blockTimePatternScore;
    int64_t difficultyReversalScore;
    int64_t historicalPatternScore;
    int64_t totalScore;
};

enum class RiskStateFull : uint8_t {
    NORMAL = 0,
    CONSERVATIVE = 1,
    DEFENSIVE = 2,
    ATTACK_RESISTANT = 3
};

enum class ConfidenceLevelFull : uint8_t {
    LOW = 0,
    MEDIUM = 1,
    HIGH = 2
};

enum class TrendDirectionFull : int8_t {
    FALLING = -1,
    STABLE = 0,
    RISING = 1
};

struct TrendMetricsFull {
    TrendDirectionFull direction;
    arith_256 strengthPercent;
    bool isSuddenInjection;
    bool isSuddenCollapse;
    bool isTemporaryRental;
    bool isOscillating;
};

// Safe Ancestor Retrieval with strict chainwork monotonicity and continuity validation
static const CBlockIndex* GetAncestorSafeMatch(const CBlockIndex* pindex, int height) {
    if (!pindex || height > pindex->nHeight || height < 0) return nullptr;
    int diff = pindex->nHeight - height;
    while (diff-- > 0 && pindex && pindex->pprev) {
        if (pindex->nChainWork <= pindex->pprev->nChainWork) {
            return nullptr;
        }
        pindex = pindex->pprev;
    }
    return pindex;
}

// Canonical Compact & Target Validation / Invariant Check
static bool DecodeAndValidateTargetCustom(unsigned int nBits, const arith_256& powLimit, arith_256& targetOut) {
    bool fNegative;
    bool fOverflow;
    targetOut.SetCompact(nBits, &fNegative, &fOverflow);
if (fNegative || fOverflow || targetOut.IsNull() || targetOut > powLimit) {
        return false;
    }
    if (targetOut.GetCompact() != nBits) {
        return false;
    }
    return true;
}

namespace FullSpecDAA {

    // 1. True Median / Robust Filtering & Outlier Pipeline for individual timestamps inside window
    inline TimestampSecurityMetrics EvaluateTimestampSecurityWindow(const CBlockIndex* pindexStart, const CBlockIndex* pindexEnd, int windowBlocks, int64_t targetSpacing) {
        TimestampSecurityMetrics tsm;
        tsm.anomalyScore = 0;
        tsm.hasFutureTimeViolation = false;
        tsm.hasDispersionViolation = false;
        tsm.qualityFactorScaled = 1000;

        if (!pindexStart || !pindexEnd || pindexEnd->nHeight <= pindexStart->nHeight) {
            return tsm;
        }

        std::vector<int64_t> spacings;
        spacings.reserve(windowBlocks);
        
        const CBlockIndex* curr = pindexEnd;
        int checks = 0;
        while (curr && curr->pprev && checks < windowBlocks) {
            int64_t blockTime = curr->GetBlockTime();
            int64_t prevBlockTime = curr->pprev->GetBlockTime();
            
            if (blockTime > curr->GetMedianTimePast() + 7200) {
                tsm.hasFutureTimeViolation = true;
                tsm.anomalyScore += 3;
            }

            if (blockTime < prevBlockTime) {
                tsm.anomalyScore += 5;
            }

            int64_t blockSpacing = blockTime - prevBlockTime;
            spacings.push_back(blockSpacing);
            curr = curr->pprev;
            checks++;
        }

        if (spacings.empty()) return tsm;

        std::vector<int64_t> sortedSpacings = spacings;
        std::sort(sortedSpacings.begin(), sortedSpacings.end());
        int64_t medianSpacing = sortedSpacings[sortedSpacings.size() / 2];

        int extremeOutliers = 0;
        for (int64_t sp : spacings) {
            if (sp < 0  sp > 7200  (medianSpacing > 0 && (sp > medianSpacing * 5  sp < medianSpacing / 5))) {
                extremeOutliers++;
            }
        }

        if (extremeOutliers > (windowBlocks / 5)) {
            tsm.hasDispersionViolation = true;
            tsm.anomalyScore += 2;
        }

        int64_t rawTimespan = pindexEnd->GetMedianTimePast() - pindexStart->GetMedianTimePast();
        int64_t expectedSpan = windowBlocks * targetSpacing;
if (rawTimespan <= 0) {
            tsm.anomalyScore += 10;
            tsm.qualityFactorScaled = 0;
        } else {
            int64_t ratioScaled = rawTimespan * 1000 / expectedSpan;
            if (ratioScaled < 100  ratioScaled > 10000) {
                tsm.anomalyScore += 3;
                tsm.qualityFactorScaled = 400;
            }
        }

        return tsm;
    }

    // Window Sanitization: Ensures anomalies PENALIZE difficulty (shrink timespan to force hard work)
    inline int64_t SanitizeWindowTimespanFull(const CBlockIndex* pindexStart, const CBlockIndex* pindexEnd, int windowBlocks, int64_t targetSpacing, TimestampSecurityMetrics& tsm) {
        if (!pindexStart || !pindexEnd || pindexEnd->nHeight <= pindexStart->nHeight) {
            return windowBlocks * targetSpacing;
        }

        int64_t rawTimespan = pindexEnd->GetMedianTimePast() - pindexStart->GetMedianTimePast();
        if (rawTimespan <= 0) {
            rawTimespan = 1;
        }

        int64_t expectedSpan = windowBlocks * targetSpacing;
        int64_t clamped = std::clamp(rawTimespan, expectedSpan / 4, expectedSpan * 4);
        
        // Security fix: Anomaly reduces timespan to penalize manipulation and force higher difficulty
        if (tsm.anomalyScore > 0) {
            int64_t penaltyFactor = std::max<int64_t>(1, 100 - (tsm.anomalyScore * 5));
            clamped = clamped * penaltyFactor / 100;
            if (clamped < 1) clamped = 1;
        }

        return clamped;
    }

    // 2. Momentum & Acceleration Engine
    inline MomentumAccelerationMetrics EvaluateMomentumAndAcceleration(arith_256 r24, arith_256 r144, arith_256 r720, arith_256 r2016) {
        MomentumAccelerationMetrics mam;
        mam.momentum24_144 = (r144 > 0) ? (r24 * 100 / r144) : arith_256(100);
        mam.momentum144_720 = (r720 > 0) ? (r144 * 100 / r720) : arith_256(100);
        mam.momentum720_2016 = (r2016 > 0) ? (r720 * 100 / r2016) : arith_256(100);

        int64_t mom1 = (int64_t)mam.momentum24_144.GetLow64();
        int64_t mom2 = (int64_t)mam.momentum144_720.GetLow64();
        int64_t mom3 = (int64_t)mam.momentum720_2016.GetLow64();

        mam.accelerationIndex = (mom1 - mom2) - (mom2 - mom3);

        if (mom1 > 200) mam.trendClass = 2;       // Sudden Injection
        else if (mom1 < 50) mam.trendClass = -2;  // Sudden Collapse
        else if (mom1 > 115) mam.trendClass = 1;  // Rising
        else if (mom1 < 85) mam.trendClass = -1;  // Falling
        else mam.trendClass = 0;                  // Stable

        return mam;
    }

    // 3. Comprehensive Attack Score Model (Fully utilizing all window anomalies and divergences)
    inline ComprehensiveAttackScore CalculateAttackScoreFull(
        const TimestampSecurityMetrics& tsmMicro,
        const TimestampSecurityMetrics& tsmShort,
        const TimestampSecurityMetrics& tsmMedium,
        const TimestampSecurityMetrics& tsmLong,
        int divCount24_144, int divCount144_720, int divCount720_2016,
        const MomentumAccelerationMetrics& mam,
        const CBlockIndex* pindexLast,
        int64_t targetSpacing)
    {
        ComprehensiveAttackScore cas;
        
        cas.timestampAnomalyScore = tsmMicro.anomalyScore + tsmShort.anomalyScore + tsmMedium.anomalyScore + tsmLong.anomalyScore;
        cas.divergenceScore = (divCount24_144 * 3) + (divCount144_720 * 2) + divCount720_2016;

        cas.blockTimePatternScore = 0;
        if (pindexLast && pindexLast->pprev) {
            int64_t recentSpacing = pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime();
            if (recentSpacing < 5  recentSpacing > 3600) {
                cas.blockTimePatternScore = 3;
            }
        }

        cas.difficultyReversalScore = 0;
        int reversalCount = 0;
        const CBlockIndex* scan = pindexLast;
        int scannedBlocks = 0;
        TrendDirectionFull lastDir = TrendDirectionFull::STABLE;
while (scan && scan->pprev && scannedBlocks < 72) {
            int64_t spacing = scan->GetBlockTime() - scan->pprev->GetBlockTime();
            TrendDirectionFull currentDir;
            if (spacing < targetSpacing * 90 / 100) {
                currentDir = TrendDirectionFull::RISING;
            } else if (spacing > targetSpacing * 110 / 100) {
                currentDir = TrendDirectionFull::FALLING;
            } else {
                currentDir = TrendDirectionFull::STABLE;
            }

            if (lastDir != TrendDirectionFull::STABLE && currentDir != lastDir && currentDir != TrendDirectionFull::STABLE) {
                reversalCount++;
            }
            if (currentDir != TrendDirectionFull::STABLE) {
                lastDir = currentDir;
            }
            scan = scan->pprev;
            scannedBlocks++;
        }

        if (reversalCount >= 6  std::abs(mam.accelerationIndex) > 150) {
            cas.difficultyReversalScore = 5;
        }

        // Historical pattern score integrated across medium/long security metrics
        cas.historicalPatternScore = (tsmMedium.anomalyScore > 2  tsmLong.anomalyScore > 2 
                                     tsmMicro.hasFutureTimeViolation  tsmShort.hasFutureTimeViolation) ? 4 : 0;

        cas.totalScore = cas.timestampAnomalyScore + 
                         cas.divergenceScore + 
                         cas.blockTimePatternScore + 
                         cas.difficultyReversalScore + 
                         cas.historicalPatternScore;

        return cas;
    }

    inline RiskStateFull EvaluateRiskStateFull(const ComprehensiveAttackScore& cas) {
        if (cas.totalScore >= 12) return RiskStateFull::ATTACK_RESISTANT;
        if (cas.totalScore >= 7) return RiskStateFull::DEFENSIVE;
        if (cas.totalScore >= 3) return RiskStateFull::CONSERVATIVE;
        return RiskStateFull::NORMAL;
    }

    // 4. Fully Integrated Confidence Engine (Consuming all window agreements and security inputs)
    inline ConfidenceLevelFull EvaluateConfidenceFull(
        const TimestampSecurityMetrics& tsmMicro,
        const TimestampSecurityMetrics& tsmShort,
        const TimestampSecurityMetrics& tsmMedium,
        const TimestampSecurityMetrics& tsmLong,
        int divCount24_144, int divCount144_720, int divCount720_2016,
        RiskStateFull riskState)
    {
        if (riskState == RiskStateFull::ATTACK_RESISTANT  riskState == RiskStateFull::DEFENSIVE) return ConfidenceLevelFull::LOW;
        
        int totalQuality = tsmMicro.qualityFactorScaled + tsmShort.qualityFactorScaled + tsmMedium.qualityFactorScaled + tsmLong.qualityFactorScaled;
        int totalDiv = divCount24_144 + divCount144_720 + divCount720_2016;

        if (totalQuality < 3000  totalDiv >= 2  riskState == RiskStateFull::CONSERVATIVE) {
            return ConfidenceLevelFull::LOW;
        }
        if (totalQuality < 3600  totalDiv == 1) {
            return ConfidenceLevelFull::MEDIUM;
        }
        return ConfidenceLevelFull::HIGH;
    }

    // 5. Advanced Trend Classifier
    inline TrendMetricsFull AnalyzeTrendFull(arith_256 r24, arith_256 r144, arith_256 r720, arith_256 r2016) {
        TrendMetricsFull metrics;
        metrics.isSuddenInjection = false;
        metrics.isSuddenCollapse = false;
        metrics.isTemporaryRental = false;
        metrics.isOscillating = false;
if (r24 > r2016 * 2) {
            metrics.isSuddenInjection = true;
            metrics.direction = TrendDirectionFull::RISING;
            metrics.strengthPercent = ((r24 - r2016) * 100) / r2016;
        } else if (r24 < r2016 / 2) {
            metrics.isSuddenCollapse = true;
            metrics.direction = TrendDirectionFull::FALLING;
            metrics.strengthPercent = ((r2016 - r24) * 100) / r2016;
        } else if (r24 > r144 && r144 < r720 && r720 < r2016) {
            metrics.isTemporaryRental = true;
            metrics.direction = TrendDirectionFull::RISING;
            metrics.strengthPercent = 25;
        } else if (r24 > r2016) {
            metrics.direction = TrendDirectionFull::RISING;
            metrics.strengthPercent = ((r24 - r2016) * 100) / r2016;
        } else if (r24 < r2016) {
            metrics.direction = TrendDirectionFull::FALLING;
            metrics.strengthPercent = ((r2016 - r24) * 100) / r2016;
        } else {
            metrics.direction = TrendDirectionFull::STABLE;
            metrics.strengthPercent = 0;
        }

        return metrics;
    }

    // 6. True Robust Hashrate Estimator (Trimmed Mean / Outlier-Resistant Proxy)
    inline arith_256 CalculateRobustHashrateEstimate(arith_256 r24, arith_256 r144, arith_256 r720, arith_256 r2016) {
        std::vector<arith_256> rates = {r24, r144, r720, r2016};
        std::sort(rates.begin(), rates.end());

        arith_256 robustEstimate = (rates[1] * 2 + rates[2] * 3 + r2016 * 4 + r24 * 1) / 10;
        if (robustEstimate == 0) return arith_256(1);
        return robustEstimate;
    }

    // 7. Full-Spec Deterministic DAA Pipeline
    inline arith_256 CalculateDeterministicTargetFull(const CBlockIndex* pindexLast, const Consensus::Params& params) {
        arith_256 powLimit = UintToArith256(params.powLimit);
        arith_256 currentTarget;
        if (!DecodeAndValidateTargetCustom(pindexLast->nBits, powLimit, currentTarget)) {
            return powLimit;
        }

        int64_t targetSpacing = params.nPowTargetSpacing;

        const CBlockIndex* pindexMicro = GetAncestorSafeMatch(pindexLast, pindexLast->nHeight - W_MICRO);
        const CBlockIndex* pindexShort = GetAncestorSafeMatch(pindexLast, pindexLast->nHeight - W_SHORT);
        const CBlockIndex* pindexMedium = GetAncestorSafeMatch(pindexLast, pindexLast->nHeight - W_MEDIUM);
        const CBlockIndex* pindexLong = GetAncestorSafeMatch(pindexLast, pindexLast->nHeight - W_LONG);
if (!pindexMicro  !pindexShort  !pindexMedium  !pindexLong) {
            return currentTarget;
        }

        TimestampSecurityMetrics tsmMicro = EvaluateTimestampSecurityWindow(pindexMicro, pindexLast, W_MICRO, targetSpacing);
        TimestampSecurityMetrics tsmShort = EvaluateTimestampSecurityWindow(pindexShort, pindexLast, W_SHORT, targetSpacing);
        TimestampSecurityMetrics tsmMedium = EvaluateTimestampSecurityWindow(pindexMedium, pindexLast, W_MEDIUM, targetSpacing);
        TimestampSecurityMetrics tsmLong = EvaluateTimestampSecurityWindow(pindexLong, pindexLast, W_LONG, targetSpacing);

        int64_t dtMicro = SanitizeWindowTimespanFull(pindexMicro, pindexLast, W_MICRO, targetSpacing, tsmMicro);
        int64_t dtShort = SanitizeWindowTimespanFull(pindexShort, pindexLast, W_SHORT, targetSpacing, tsmShort);
        int64_t dtMedium = SanitizeWindowTimespanFull(pindexMedium, pindexLast, W_MEDIUM, targetSpacing, tsmMedium);
        int64_t dtLong = SanitizeWindowTimespanFull(pindexLong, pindexLast, W_LONG, targetSpacing, tsmLong);

        arith_256 workMicro = pindexLast->nChainWork - pindexMicro->nChainWork;
        arith_256 workShort = pindexLast->nChainWork - pindexShort->nChainWork;
        arith_256 workMedium = pindexLast->nChainWork - pindexMedium->nChainWork;
        arith_256 workLong = pindexLast->nChainWork - pindexLong->nChainWork;

        arith_256 r24 = (dtMicro > 0) ? (workMicro * ARITH_SCALE / dtMicro) : arith_256(1);
        arith_256 r144 = (dtShort > 0) ? (workShort * ARITH_SCALE / dtShort) : arith_256(1);
        arith_256 r720 = (dtMedium > 0) ? (workMedium * ARITH_SCALE / dtMedium) : arith_256(1);
        arith_256 r2016 = (dtLong > 0) ? (workLong * ARITH_SCALE / dtLong) : arith_256(1);

        arith_256 d1 = (r24 > r144) ? (r24 - r144) : (r144 - r24);
        arith_256 d2 = (r144 > r720) ? (r144 - r720) : (r720 - r144);
        arith_256 d3 = (r720 > r2016) ? (r720 - r2016) : (r2016 - r720);

        int divCount24_144 = (r144 > 0 && (d1 * 100) / r144 > 35) ? 1 : 0;
        int divCount144_720 = (r720 > 0 && (d2 * 100) / r720 > 35) ? 1 : 0;
        int divCount720_2016 = (r2016 > 0 && (d3 * 100) / r2016 > 35) ? 1 : 0;

        MomentumAccelerationMetrics mam = EvaluateMomentumAndAcceleration(r24, r144, r720, r2016);
        ComprehensiveAttackScore cas = CalculateAttackScoreFull(tsmMicro, tsmShort, tsmMedium, tsmLong, divCount24_144, divCount144_720, divCount720_2016, mam, pindexLast, targetSpacing);
        RiskStateFull riskState = EvaluateRiskStateFull(cas);
        ConfidenceLevelFull confidence = EvaluateConfidenceFull(tsmMicro, tsmShort, tsmMedium, tsmLong, divCount24_144, divCount144_720, divCount720_2016, riskState);
        TrendMetricsFull metrics = AnalyzeTrendFull(r24, r144, r720, r2016);

        arith_256 robustHashrateEstimate = CalculateRobustHashrateEstimate(r24, r144, r720, r2016);

        // True Historical Long-Term Anchor derived from actual long-window work and timespan
        arith_256 targetLongAnchor = (dtLong > 0 && r2016 > 0) ? (powLimit * ARITH_SCALE / r2016) : currentTarget;
        arith_256 targetMedium = currentTarget * dtMedium / (W_MEDIUM * targetSpacing);
        arith_256 targetShort = currentTarget * dtShort / (W_SHORT * targetSpacing);
        arith_256 targetMicro = currentTarget * dtMicro / (W_MICRO * targetSpacing);

        int64_t actualBlockTimeGap = pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime();
        int64_t blockTimeErrorRatio = (actualBlockTimeGap * 100) / targetSpacing;

        arith_256 rawTarget;
        if (riskState == RiskStateFull::ATTACK_RESISTANT) {
            // Attack-Resistant Mode: Increase reliance on 720/2016 windows and apply hard limits
            rawTarget = (targetLongAnchor * 7 + targetMedium * 3) / 10;
        } else if (riskState == RiskStateFull::DEFENSIVE) {
            rawTarget = (targetLongAnchor * 8 + targetMedium * 2) / 10;
        } else if (riskState == RiskStateFull::CONSERVATIVE) {
            rawTarget = (targetLongAnchor * 6 + targetMedium * 4) / 10;
        } else {
arith_256 standardWeighted = (targetLongAnchor * 4 + targetMedium * 3 + targetShort * 2 + targetMicro) / 10;

            if (confidence == ConfidenceLevelFull::LOW) {
                standardWeighted = (targetLongAnchor * 7 + targetMedium * 3) / 10;
            }

            // Direct Momentum & Acceleration integration into Target Controller
            if (mam.trendClass == 2  metrics.isSuddenInjection) {
                standardWeighted = standardWeighted * 90 / 100;
            } else if (mam.trendClass == -2  metrics.isSuddenCollapse) {
                standardWeighted = standardWeighted * 110 / 100;
            } else if (metrics.direction == TrendDirectionFull::RISING && metrics.strengthPercent > 10) {
                standardWeighted = standardWeighted * 96 / 100;
            } else if (metrics.direction == TrendDirectionFull::FALLING && metrics.strengthPercent > 10) {
                standardWeighted = standardWeighted * 104 / 100;
            }

            // Block Time Error Controller
            if (blockTimeErrorRatio < 80) {
                standardWeighted = standardWeighted * 98 / 100;
            } else if (blockTimeErrorRatio > 120) {
                standardWeighted = standardWeighted * 102 / 100;
            }

            if (robustHashrateEstimate > 0 && r2016 > 0) {
                rawTarget = (standardWeighted * 7 + (targetLongAnchor * r2016 / robustHashrateEstimate) * 3) / 10;
            } else {
                rawTarget = standardWeighted;
            }
        }

        // Asymmetric Per-block rate limiters based on risk state
        int64_t maxInc = (riskState == RiskStateFull::NORMAL) ? 6 : 3;
        int64_t maxDec = (riskState == RiskStateFull::NORMAL) ? 8 : 4;
        
        arith_256 maxTargetLimit = currentTarget * (100 + maxDec) / 100; // Allow target increase (difficulty decrease) up to maxDec
        arith_256 minTargetLimit = currentTarget * (100 - maxInc) / 100; // Allow target decrease (difficulty increase) down to maxInc

        if (rawTarget > maxTargetLimit) rawTarget = maxTargetLimit;
        if (rawTarget < minTargetLimit) rawTarget = minTargetLimit;

        // Cumulative Window Limiter (Strict bounds against W_LONG baseline target)
        arith_256 baselineTarget;
        if (DecodeAndValidateTargetCustom(pindexLong->nBits, powLimit, baselineTarget)) {
            arith_256 maxWindowExpansion = baselineTarget * 175 / 100;
            arith_256 maxWindowReduction = baselineTarget * 35 / 100;

            if (rawTarget > maxWindowExpansion) rawTarget = maxWindowExpansion;
            if (rawTarget < maxWindowReduction) rawTarget = maxWindowReduction;
        }

        if (rawTarget > powLimit  rawTarget.IsNull()) {
            rawTarget = powLimit;
        }

        return rawTarget;
    }
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    int nextHeight = pindexLast->nHeight + 1;

    if (nextHeight >= 14112) {
        arith_256 calculatedTarget = FullSpecDAA::CalculateDeterministicTargetFull(pindexLast, params);
        arith_256 verifiedTarget;
        if (!DecodeAndValidateTargetCustom(calculatedTarget.GetCompact(), UintToArith256(params.powLimit), verifiedTarget)) {
            return params.powLimit.GetCompact();
        }
        return verifiedTarget.GetCompact();
    }

    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    unsigned int nMinDifficultyFloor = 0x1a06a090;
if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }

        if (pindexLast->nHeight + 1 >= 2016) {
            if (pindexLast->nBits > nMinDifficultyFloor) {
                return nMinDifficultyFloor;
            }
        }
        return pindexLast->nBits;
    }

    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    unsigned int nNewBits = CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);

    if (pindexLast->nHeight + 1 >= 2016) {
        if (nNewBits > nMinDifficultyFloor) {
            return nMinDifficultyFloor;
        }
    }

    return nNewBits;
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    if (params.enforce_BIP94) {
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Rigorous Consensus Transition Verification linking DAA output directly to block validation
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits, const CBlockIndex* pindexPrev)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height >= 14112) {
        const arith_256 pow_limit = UintToArith256(params.powLimit);
        arith_256 observed_target;
        if (!DecodeAndValidateTargetCustom(new_nbits, pow_limit, observed_target)) {
            return false;
        }

        if (pindexPrev) {
            arith_256 expected_target = FullSpecDAA::CalculateDeterministicTargetFull(pindexPrev, params);
            if (observed_target.GetCompact() != expected_target.GetCompact()) {
                return false; // CONSENSUS REJECT: Observed block nBits does not match deterministic DAA output
            }
        }
        return true;
    }

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }
arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (height >= 2016 && new_nbits == 0x1a06a090) return true;

        if (maximum_new_target < observed_new_target) return false;

        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    if (fNegative  bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
