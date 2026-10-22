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

#include "priority_notification_degrade_manager.h"

#include <algorithm>
#include <cinttypes>
#include <functional>
#include <memory>
#include <vector>

#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "errors.h"
#include "ffrt_queue_impl.h"
#include "notification_analytics_util.h"
#include "notification_classification_mgr.h"

namespace OHOS {
namespace Notification {
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
namespace {
constexpr char PRIORITY_DEGRADE_TIMER_NAME[] = "priorityDegradeTimer";
constexpr char PRIORITY_DEGRADE_LIST_CONTAINER_NAME[] = "priority_degrade_list";

bool IsRuleSource(int32_t source)
{
    return source == static_cast<int32_t>(NotificationConstant::PrioritySourceResult::KEYWORD)
        || source == static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PUSH_RULE)
        || source == static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PARAM_IN);
}

NotificationClassification::PriorityInfo EffectivePriorityInfo(
    const sptr<NotificationClassification> &classification,
    const sptr<NotificationClassification> &cached)
{
    if (classification->IsPriorityInfoSet()) {
        return classification->GetPriorityInfo();
    }
    return cached != nullptr ? cached->GetPriorityInfo() : NotificationClassification::PriorityInfo();
}
} // namespace

PriorityNotificationDegradeManager::PriorityNotificationDegradeManager()
{
    ANS_LOGD("called");
    timerScheduler_.Init(PRIORITY_DEGRADE_TIMER_NAME,
        [this]() { return GetEarliestExpiredTime(); },
        [this]() -> std::function<void()> {
            std::weak_ptr<PriorityNotificationDegradeManager> selfWeak = weak_from_this();
            if (selfWeak.lock() == nullptr) {
                return nullptr;
            }
            return [selfWeak]() {
                std::shared_ptr<PriorityNotificationDegradeManager> instance = selfWeak.lock();
                if (instance != nullptr) {
                    instance->TriggerDegrade();
                }
            };
        });
}

PriorityNotificationDegradeManager::~PriorityNotificationDegradeManager()
{
    ANS_LOGD("called");
    timerScheduler_.Disarm();
    std::lock_guard<ffrt::mutex> lock(mutex_);
    degradeList_.clear();
}

PriorityNotificationDegradeManager::ArbitrateResult PriorityNotificationDegradeManager::ApplyTaggingResult(
    const std::string &key, const sptr<NotificationRequest> &cacheRequest,
    const sptr<NotificationClassification> &classification,
    sptr<NotificationClassification> &effectiveClassification)
{
    ArbitrateResult result = ArbitrateResult::APPLY;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);

        sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
        if (classification == nullptr) {
            result = ArbitrateNullClassification(key, cached, cacheRequest, effectiveClassification);
        } else {
            NotificationClassification::PriorityInfo newInfo = EffectivePriorityInfo(classification, cached);
            result = ArbitrateAgainstCache(cached, ClassifyCacheState(key, cached), newInfo);
            if (!LandAcceptedResult(key, cached, cacheRequest, classification, result,
                effectiveClassification)) {
                return result;
            }
        }

        SyncDegradeScheduleLocked(key, effectiveClassification);
    }

    ReArmDegradeTimer();
    if (capacityAlertPending_.exchange(false)) {
        ANS_LOGW("Degrade registration list reached capacity, drop registration, capacity: "
            "%{public}zu, current size: %{public}zu", MAX_ACTIVE_NUM, capacityAlertSize_);
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_1);
        message.Message(std::string(PRIORITY_DEGRADE_LIST_CONTAINER_NAME) + "_cap_"
            + std::to_string(MAX_ACTIVE_NUM) + "_size_" + std::to_string(capacityAlertSize_));
        NotificationAnalyticsUtil::ReportModifyEvent(message);
    }
    if (capacitySweepPending_.exchange(false)) {
        sptr<AdvancedNotificationService> service = AdvancedNotificationService::GetInstance();
        if (service != nullptr) {
            service->ScheduleOrphanClassificationSweep();
        }
    }
    return result;
}

PriorityNotificationDegradeManager::ArbitrateResult PriorityNotificationDegradeManager::ArbitrateNullClassification(
    const std::string &key, const sptr<NotificationClassification> &cached,
    const sptr<NotificationRequest> &cacheRequest,
    sptr<NotificationClassification> &effectiveClassification)
{
    effectiveClassification = nullptr;
    if (cached != nullptr) {
        NotificationClassificationMgr::GetInstance().Remove(key);
    }
    if (cacheRequest != nullptr) {
        cacheRequest->SetInnerPriorityNotificationType(
            NotificationConstant::PriorityNotificationType::OTHER);
    }
    return ArbitrateResult::CLEARED;
}

PriorityNotificationDegradeManager::CacheState PriorityNotificationDegradeManager::ClassifyCacheState(
    const std::string &key, const sptr<NotificationClassification> &cached)
{
    if (cached == nullptr) {
        return CacheState::NONE;
    }
    NotificationClassification::PriorityInfo cachedInfo = cached->GetPriorityInfo();
    if (cachedInfo.GetExpiredTime() <= 0
        || (cachedInfo.GetSource()
            == static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT)
            && cachedInfo.GetPriorityNotificationType()
                != NotificationConstant::PriorityNotificationType::OTHER)) {
        return CacheState::UNDETERMINED;
    }

    if (cachedInfo.GetPriorityNotificationType()
        == NotificationConstant::PriorityNotificationType::OTHER) {
        return CacheState::TERMINAL;
    }
    return CacheState::DETERMINED;
}

PriorityNotificationDegradeManager::ArbitrateResult PriorityNotificationDegradeManager::ArbitrateAgainstCache(
    const sptr<NotificationClassification> &cached, CacheState state,
    const NotificationClassification::PriorityInfo &newInfo)
{
    switch (state) {
        case CacheState::NONE:
        case CacheState::UNDETERMINED:
            return ArbitrateResult::APPLY;
        case CacheState::DETERMINED:
        case CacheState::TERMINAL:
        default:
            break;
    }

    NotificationClassification::PriorityInfo cachedInfo = cached->GetPriorityInfo();
    if (cachedInfo.GetSource() == static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI)
        && IsRuleSource(newInfo.GetSource())) {
        return ArbitrateResult::RULE_OVERRIDE;
    }

    return ArbitrateResult::APPLY;
}

bool PriorityNotificationDegradeManager::LandAcceptedResult(const std::string &key,
    const sptr<NotificationClassification> &cached, const sptr<NotificationRequest> &cacheRequest,
    const sptr<NotificationClassification> &classification, ArbitrateResult &result,
    sptr<NotificationClassification> &effectiveClassification)
{
    NotificationClassification::PriorityInfo newInfo = EffectivePriorityInfo(classification, cached);

    sptr<NotificationClassification> landingInput = classification;
    bool landingPrepared = true;
    if (classification->IsPriorityInfoSet()) {
        int64_t now = NotificationAnalyticsUtil::GetCurrentTime();
        int64_t expireTimeUpperBound = now + PRIORITY_EXPIRE_TIME_MAX_HORIZON_MS;
        bool tripleChanged = false;
        if (newInfo.GetExpiredTime() > expireTimeUpperBound) {
            newInfo.SetExpiredTime(expireTimeUpperBound);
            tripleChanged = true;
        }

        if (cached != nullptr
            && newInfo.GetPriorityNotificationType() == cached->GetPriorityInfo().GetPriorityNotificationType()
            && cached->GetPriorityInfo().GetExpiredTime() > 0) {
            newInfo.SetExpiredTime(cached->GetPriorityInfo().GetExpiredTime());
            tripleChanged = true;
        }

        if (newInfo.GetPriorityNotificationType() == NotificationConstant::PriorityNotificationType::OTHER
            && newInfo.GetExpiredTime() != 0) {
            newInfo.SetExpiredTime(0);
            tripleChanged = true;
        }

        if (newInfo.GetPriorityNotificationType() != NotificationConstant::PriorityNotificationType::OTHER
            && newInfo.GetExpiredTime() > 0
            && newInfo.GetExpiredTime() <= now) {
            ANS_LOGW("Priority type already expired at landing, land as degraded terminal, "
                "key: %{public}s, type: %{public}s, expiredTime: %{public}" PRId64,
                key.c_str(), newInfo.GetPriorityNotificationType().c_str(), newInfo.GetExpiredTime());
            newInfo.SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::OTHER);
            if (cacheRequest != nullptr) {
                cacheRequest->SetInnerPriorityNotificationType(
                    NotificationConstant::PriorityNotificationType::OTHER);
            }
            tripleChanged = true;
        }

        if (tripleChanged) {
            sptr<NotificationClassification> transformed =
                new (std::nothrow) NotificationClassification(*classification);
            if (transformed != nullptr) {
                transformed->SetPriorityInfo(newInfo);
                landingInput = transformed;
            } else {
                landingPrepared = false;
            }
        }
    }

    sptr<NotificationClassification> landed = landingPrepared
        ? NotificationClassificationMgr::GetInstance().AddOrUpdate(key, landingInput)
        : nullptr;
    if (landed == nullptr) {
        ANS_LOGE("Landing classification failed (round copy, merge allocation or cache capacity), keep "
            "the cached value and drop the round, key: %{public}s", key.c_str());
        effectiveClassification = cached;
        if (cacheRequest != nullptr && cached != nullptr) {
            cacheRequest->SetInnerPriorityNotificationType(
                cached->GetPriorityInfo().GetPriorityNotificationType());
        }
        bool cacheAlreadyDegraded = cached != nullptr
            && cached->GetPriorityInfo().GetPriorityNotificationType()
                == NotificationConstant::PriorityNotificationType::OTHER;
        result = cacheAlreadyDegraded ? ArbitrateResult::DROP_DEGRADED
            : ArbitrateResult::DROP_IMMUTABLE;
        return false;
    }
    effectiveClassification = landed;
    return true;
}

void PriorityNotificationDegradeManager::SyncDegradeScheduleLocked(const std::string &key,
    const sptr<NotificationClassification> &landed)
{
    size_t sizeBefore = degradeList_.size();
    degradeList_.remove_if([&key](const DegradeRecord &record) { return record.key == key; });
    size_t removedCount = sizeBefore - degradeList_.size();
    int64_t expiredTime = 0;
    if (ResolveScheduleActionLocked(key, landed, expiredTime) == ScheduleAction::REGISTER) {
        UpsertDegradeRecordLocked(key, expiredTime);
    }
    if (removedCount > 0) {
        ANS_LOGD("Degrade registration removed for reschedule, key: %{public}s, "
            "removed count: %{public}zu", key.c_str(), removedCount);
    }
}

PriorityNotificationDegradeManager::ScheduleAction PriorityNotificationDegradeManager::ResolveScheduleActionLocked(
    const std::string &key, const sptr<NotificationClassification> &landed, int64_t &expiredTime)
{
    if (landed == nullptr) {
        return ScheduleAction::NONE;
    }
    expiredTime = landed->GetPriorityInfo().GetExpiredTime();
    if (landed->GetPriorityInfo().GetPriorityNotificationType()
            == NotificationConstant::PriorityNotificationType::OTHER
        && expiredTime > 0) {
        return ScheduleAction::NONE;
    }
    if (expiredTime > NotificationAnalyticsUtil::GetCurrentTime()) {
        return ScheduleAction::REGISTER;
    }
    if (expiredTime > 0) {
        ANS_LOGW("Expired triple at schedule resolve, skip registration, key: %{public}s, "
            "expiredTime: %{public}" PRId64, key.c_str(), expiredTime);
    }
    return ScheduleAction::NONE;
}

void PriorityNotificationDegradeManager::UpsertDegradeRecordLocked(const std::string &key,
    int64_t expiredTime)
{
    if (degradeList_.size() >= MAX_ACTIVE_NUM) {
        if (!capacityAlerted_) {
            capacityAlerted_ = true;
            capacityAlertSize_ = degradeList_.size();
            capacityAlertPending_ = true;
        }
        capacitySweepPending_ = true;
        return;
    }

    DegradeRecord record;
    record.key = key;
    record.expiredTime = expiredTime;
    if (degradeList_.empty() || degradeList_.back().expiredTime <= expiredTime) {
        degradeList_.push_back(record);
        return;
    }
    auto insertPos = std::upper_bound(degradeList_.begin(), degradeList_.end(), expiredTime,
        [](int64_t value, const DegradeRecord &entry) { return value < entry.expiredTime; });
    degradeList_.insert(insertPos, record);
}

void PriorityNotificationDegradeManager::Remove(const std::string &key)
{
    size_t removedCount = 0;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        size_t sizeBefore = degradeList_.size();
        degradeList_.remove_if([&key](const DegradeRecord &record) { return record.key == key; });
        removedCount = sizeBefore - degradeList_.size();
    }

    if (removedCount > 0) {
        ANS_LOGD("Degrade registration removed, key: %{public}s, removed count: %{public}zu",
            key.c_str(), removedCount);
    }

    ReArmDegradeTimer();
}

void PriorityNotificationDegradeManager::RemoveOrphans(const std::set<std::string> &liveKeys)
{
    size_t removedCount = 0;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        size_t sizeBefore = degradeList_.size();
        degradeList_.remove_if([&liveKeys](const DegradeRecord &record) {
            return liveKeys.find(record.key) == liveKeys.end();
        });
        removedCount = sizeBefore - degradeList_.size();
    }

    if (removedCount > 0) {
        ANS_LOGD("Degrade registration orphan sweep, removed count: %{public}zu", removedCount);
    }

    ReArmDegradeTimer();
}

void PriorityNotificationDegradeManager::TriggerDegrade()
{
    timerScheduler_.Disarm();

    int64_t now = NotificationAnalyticsUtil::GetCurrentTime();
    std::vector<std::string> dueKeys;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        dueKeys = CollectExpiredRecordsLocked(now);
    }

    DispatchExpiredRecords(dueKeys);

    ReArmDegradeTimer();
}

bool PriorityNotificationDegradeManager::IsPriorityDegradeDue(
    const sptr<NotificationClassification> &cachedClassification)
{
    if (cachedClassification == nullptr) {
        return true;
    }
    int64_t cachedExpiredTime = cachedClassification->GetPriorityInfo().GetExpiredTime();
    if (cachedExpiredTime <= 0) {
        return false;
    }
    return cachedExpiredTime <= NotificationAnalyticsUtil::GetCurrentTime();
}

sptr<NotificationClassification> PriorityNotificationDegradeManager::DegradeClassificationCache(
    const std::string &key, const sptr<NotificationClassification> &cachedClassification)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    sptr<NotificationClassification> current = NotificationClassificationMgr::GetInstance().Get(key);
    if (current == nullptr) {
        ANS_LOGI("Priority degrade skip, cache entry already cleared, key: %{public}s", key.c_str());
        return nullptr;
    }
    if (current->GetPriorityInfo().GetPriorityNotificationType()
            != cachedClassification->GetPriorityInfo().GetPriorityNotificationType()
        || current->GetPriorityInfo().GetExpiredTime()
            != cachedClassification->GetPriorityInfo().GetExpiredTime()) {
        ANS_LOGI("Priority degrade skip, revived by a newer round, key: %{public}s", key.c_str());
        return nullptr;
    }
    sptr<NotificationClassification> degradeRound = new (std::nothrow) NotificationClassification();
    if (degradeRound == nullptr) {
        ANS_LOGW("Priority degrade fail, null degrade round, key: %{public}s", key.c_str());
        return nullptr;
    }
    NotificationClassification::PriorityInfo priorityInfo = cachedClassification->GetPriorityInfo();
    priorityInfo.SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::OTHER);
    degradeRound->SetPriorityInfo(priorityInfo);
    sptr<NotificationClassification> degraded =
        NotificationClassificationMgr::GetInstance().AddOrUpdate(key, degradeRound);
    if (degraded == nullptr) {
        ANS_LOGW("Priority degrade fail, null degraded classification, key: %{public}s", key.c_str());
    }
    return degraded;
}

void PriorityNotificationDegradeManager::DegradePriorityCacheWithoutRequest(
    const std::string &key, const sptr<NotificationClassification> &cachedClassification)
{
    ANS_LOGW("Priority degrade cache request not exist, key: %{public}s", key.c_str());
    if (cachedClassification != nullptr) {
        DegradeClassificationCache(key, cachedClassification);
    }
}

std::vector<std::string> PriorityNotificationDegradeManager::CollectExpiredRecordsLocked(int64_t now)
{
    std::vector<std::string> dueKeys;

    for (auto iter = degradeList_.begin(); iter != degradeList_.end();) {
        if (iter->expiredTime <= now) {
            dueKeys.emplace_back(iter->key);
            iter = degradeList_.erase(iter);
            continue;
        }
        break;
    }
    return dueKeys;
}

void PriorityNotificationDegradeManager::DispatchExpiredRecords(const std::vector<std::string> &dueKeys)
{
    sptr<AdvancedNotificationService> service = AdvancedNotificationService::GetInstance();
    if (service == nullptr) {
        ANS_LOGW("Service instance unavailable, skip degrade dispatch, due count: %{public}zu",
            dueKeys.size());
    } else if (!dueKeys.empty()) {
        Infra::FfrtQueueImpl svrQueue = service->GetNotificationSvrQueue();
        auto submitResult = svrQueue.SyncSubmit([dueKeys, service] {
            for (const auto &dueKey : dueKeys) {
                service->ProcessPriorityDegradeOnQueue(dueKey);
            }
        });

        ANS_COND_DO_ERR(submitResult != ERR_OK, (void)0,
            "Submit degrade batch task failed, due count: %{public}zu", dueKeys.size());
    }
}

void PriorityNotificationDegradeManager::ReArmDegradeTimer()
{
    timerScheduler_.ReArm();
}

int64_t PriorityNotificationDegradeManager::GetEarliestExpiredTime()
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    if (degradeList_.empty()) {
        return 0;
    }

    return degradeList_.front().expiredTime;
}
#endif // ANS_FEATURE_PRIORITY_NOTIFICATION
} // namespace Notification
} // namespace OHOS
