/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_PRIORITY_NOTIFICATION_DEGRADE_MANAGER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_PRIORITY_NOTIFICATION_DEGRADE_MANAGER_H

#include <atomic>
#include <list>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ffrt.h"
#include "notification_classification.h"
#include "notification_request.h"
#include "refbase.h"
#include "singleton.h"
#include "single_timer_scheduler.h"

namespace OHOS {
namespace Notification {
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION

constexpr int64_t PRIORITY_EXPIRE_TIME_MAX_HORIZON_MS = 72LL * 60 * 60 * 1000;

/**
 * Arbitrates every tagging round against the classification cache, lands the
 * winning triple and keeps the timed degrade registration in sync. The
 * registration list is bounded by MAX_ACTIVE_NUM (reported once through the
 * SCENE_30 analytics event when the bound rejects a registration).
 */
class PriorityNotificationDegradeManager
    : public DelayedSingleton<PriorityNotificationDegradeManager>,
      public std::enable_shared_from_this<PriorityNotificationDegradeManager> {
public:
    enum class ArbitrateResult {
        APPLY,
        RULE_OVERRIDE,
        DROP_IMMUTABLE,
        DROP_DEGRADED,
        /** Null round only: the cache entry is removed (aggregation labels included)
         *  and the request type is forced to OTHER. */
        CLEARED,
    };

    /**
     * @brief Arbitrates one tagging result and lands the winning triple (unified
     *        entry, whole sequence under mutex_, lock order mutex_ then the
     *        classification manager mutex).
     *
     * @param key Indicates the notification key, same as the classification cache key.
     * @param cacheRequest Indicates the cached request, its type is forced back to the
     *        landed (or cleared) one by the drop family and the null round.
     * @param classification Indicates the incoming tagging result; null means a null
     *        round (entry removed, type forced to OTHER). The two dimension flags
     *        decide which dimension the round overwrites; a non null round wins over
     *        any cached state, including the degraded terminal (revive semantics).
     * @param effectiveClassification Indicates the out effective value: the landed new
     *        value for APPLY / RULE_OVERRIDE, the cached value on a landing failure,
     *        null for a null round.
     * @return Returns the arbitration outcome of the incoming result.
     */
    ArbitrateResult ApplyTaggingResult(const std::string &key,
        const sptr<NotificationRequest> &cacheRequest,
        const sptr<NotificationClassification> &classification,
        sptr<NotificationClassification> &effectiveClassification);

    /**
     * @brief Removes the degrade registration of one notification.
     *
     * @param key Indicates the notification key.
     */
    void Remove(const std::string &key);

    /**
     * @brief Removes every registration whose key is not in liveKeys (orphan sweep,
     *        notificationSvrQueue_ context).
     *
     * @param liveKeys Indicates the keys of the live notifications.
     */
    void RemoveOrphans(const std::set<std::string> &liveKeys);

    /**
     * @brief Timer expiry callback: strips every due registration in batch under the
     *        lock and degrades them through one synchronous submit onto
     *        notificationSvrQueue_ out of the lock. Also callable by unit tests.
     */
    void TriggerDegrade();

    /**
     * @brief Expiry defense: the degrade is due only when the cached triple carries a
     *        determined expire time that already came due (0 < expiredTime <= now); a
     *        null cache keeps the legacy defensive behavior (proceeds).
     *
     * @param cachedClassification Indicates the cached classification snapshot, may be null.
     * @return Returns true if the degrade should proceed.
     */
    bool IsPriorityDegradeDue(const sptr<NotificationClassification> &cachedClassification);

    /**
     * @brief Degrades the cached triple to the terminal (type OTHER) by compare-and-land:
     *        the re-read, compare and land sequence runs under mutex_, a newer round
     *        revived or cleared entry wins and the landing gives up.
     *
     * @param key Indicates the key of the notification being degraded.
     * @param cachedClassification Indicates the caller's cache snapshot, must not be null.
     * @return Returns the landed degraded entry; null when the snapshot is stale or on
     *         allocation failure (cache untouched).
     */
    sptr<NotificationClassification> DegradeClassificationCache(const std::string &key,
        const sptr<NotificationClassification> &cachedClassification);

    /**
     * @brief Defensive degrade landing without the cached request: keeps the degrade
     *        point terminal without the request landing and the subscriber callback.
     *
     * @param key Indicates the key of the notification being degraded.
     * @param cachedClassification Indicates the cached classification snapshot, may be null.
     */
    void DegradePriorityCacheWithoutRequest(const std::string &key,
        const sptr<NotificationClassification> &cachedClassification);

private:
    struct DegradeRecord {
        std::string key;
        int64_t expiredTime {0};
    };

    enum class CacheState {
        NONE,
        UNDETERMINED,
        DETERMINED,
        TERMINAL,
    };

    enum class ScheduleAction {
        NONE,
        REGISTER,
    };

    /**
     * @brief Null round handling (in-lock): removes the cached entry, forces the
     *        request type to OTHER, returns CLEARED.
     */
    ArbitrateResult ArbitrateNullClassification(const std::string &key,
        const sptr<NotificationClassification> &cached,
        const sptr<NotificationRequest> &cacheRequest,
        sptr<NotificationClassification> &effectiveClassification);

    /**
     * @brief Normalizes the cached state (in-lock): NONE / UNDETERMINED (refreshable,
     *        incoherent triple) / TERMINAL (degrade marker) / DETERMINED.
     */
    CacheState ClassifyCacheState(const std::string &key,
        const sptr<NotificationClassification> &cached);

    /**
     * @brief Maps the cache state and the incoming triple to the outcome (in-lock):
     *        APPLY for NONE / UNDETERMINED / DETERMINED (RULE_OVERRIDE only for a rule
     *        family result against an undegraded model cache), TERMINAL revives.
     */
    ArbitrateResult ArbitrateAgainstCache(const sptr<NotificationClassification> &cached,
        CacheState state, const NotificationClassification::PriorityInfo &newInfo);

    /**
     * @brief Lands an accepted round (in-lock) with the policy transforms: expire time
     *        clamped to the 72h horizon, a repeated type keeps the cached expire time,
     *        type OTHER normalized to expireTime 0, an already expired triple lands
     *        directly as the terminal (the landing itself is the degrade). On
     *        allocation failure the cache stays untouched, the effective value falls
     *        back to the cached one and result is revised to the drop outcome.
     *
     * @return Returns true when the landing completed; false means the caller must
     *         return early without the schedule sync.
     */
    bool LandAcceptedResult(const std::string &key, const sptr<NotificationClassification> &cached,
        const sptr<NotificationRequest> &cacheRequest,
        const sptr<NotificationClassification> &classification, ArbitrateResult &result,
        sptr<NotificationClassification> &effectiveClassification);

    /**
     * @brief Syncs the registration of one key with the landed snapshot (in-lock, same
     *        critical section as the landing): a determined future expire time
     *        registers, anything else strips; the timer is re-armed by the caller
     *        after the lock.
     */
    void SyncDegradeScheduleLocked(const std::string &key,
        const sptr<NotificationClassification> &landed);

    /**
     * @brief Resolves the schedule action from the landed snapshot (in-lock).
     */
    ScheduleAction ResolveScheduleActionLocked(const std::string &key,
        const sptr<NotificationClassification> &landed, int64_t &expiredTime);

    /**
     * @brief Registers the degrade record keeping the list ascending (in-lock); the
     *        entry count is bounded by MAX_ACTIVE_NUM, a registration at capacity is
     *        dropped, reported once through the SCENE_30 analytics event and an
     *        orphan sweep against the live notifications is scheduled.
     */
    void UpsertDegradeRecordLocked(const std::string &key, int64_t expiredTime);

    /**
     * @brief Re-arms the single timer with the earliest expire time. Call sites must
     *        sit outside any mutex_ critical section (lock order: the scheduler mutex
     *        first, then mutex_, one way).
     */
    void ReArmDegradeTimer();

    /**
     * @brief Strips every due registration and collects their keys (in-lock, the list
     *        is ascending so the strip stops at the first not-yet-due record).
     */
    std::vector<std::string> CollectExpiredRecordsLocked(int64_t now);

    /**
     * @brief Dispatches the whole due batch through one synchronous submit onto the
     *        server queue (out of any lock); a submit failure keeps the loss
     *        semantics (the registrations were already stripped).
     */
    void DispatchExpiredRecords(const std::vector<std::string> &dueKeys);

    /**
     * @brief Gets the earliest (list front) absolute expire time, 0 when empty.
     */
    int64_t GetEarliestExpiredTime();

    std::list<DegradeRecord> degradeList_;
    ffrt::mutex mutex_;
    bool capacityAlerted_ {false};
    std::atomic<bool> capacityAlertPending_ {false};
    std::atomic<bool> capacitySweepPending_ {false};
    size_t capacityAlertSize_ {0};

    SingleTimerScheduler timerScheduler_;

    DECLARE_DELAYED_SINGLETON(PriorityNotificationDegradeManager);
    DISALLOW_COPY_AND_MOVE(PriorityNotificationDegradeManager);
};
#endif // ANS_FEATURE_PRIORITY_NOTIFICATION
} // namespace Notification
} // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_PRIORITY_NOTIFICATION_DEGRADE_MANAGER_H
