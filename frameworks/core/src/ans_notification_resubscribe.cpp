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

#include "ans_notification.h"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <set>
#include <utility>

#include "ans_log_wrapper.h"
#include "ans_manager_death_recipient.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr uint32_t RESUBSCRIBE_MAX_RETRY_TIMES = 4;
constexpr uint32_t RESUBSCRIBE_RETRY_BASE_INTERVAL_MS = 500;
constexpr uint32_t RESUBSCRIBE_RETRY_MAX_INTERVAL_MS = 4000;

enum class RemainingFilterResult {
    UPDATED,
    EMPTY,
    UNSUPPORTED,
    FAILED,
};

template <typename T>
std::vector<T> RemoveValues(const std::vector<T> &source, const std::vector<T> &removed)
{
    std::set<T> removedSet(removed.begin(), removed.end());
    std::vector<T> remaining;
    remaining.reserve(source.size());
    for (const auto &value : source) {
        if (removedSet.find(value) == removedSet.end()) {
            remaining.emplace_back(value);
        }
    }
    return remaining;
}

bool IsSubscribeAll(const sptr<NotificationSubscribeInfo> &info)
{
    return info != nullptr && info->GetAppNames().empty() && info->GetAppUids().empty();
}

std::pair<size_t, size_t> GetSubscribeFilterSize(const sptr<NotificationSubscribeInfo> &info)
{
    if (info == nullptr) {
        return {0, 0};
    }
    return {info->GetAppNames().size(), info->GetAppUids().size()};
}

sptr<NotificationSubscribeInfo> CopySubscribeInfo(const sptr<NotificationSubscribeInfo> &source,
    const std::vector<std::string> &appNames, const std::vector<int32_t> &appUids)
{
    sptr<NotificationSubscribeInfo> info = new (std::nothrow) NotificationSubscribeInfo();
    if (info == nullptr) {
        return nullptr;
    }
    info->AddAppNames(appNames);
    info->AddAppUids(appUids);
    info->AddAppUserId(source->GetAppUserId());
    info->AddDeviceType(source->GetDeviceType());
    info->SetSlotTypes(source->GetSlotTypes());
    info->SetFilterType(source->GetFilterType());
    info->SetNeedNotifyApplication(source->GetNeedNotifyApplication());
    info->SetNeedNotifyResponse(source->GetNeedNotifyResponse());
    info->SetIsSubscribeSelf(source->GetIsSubscribeSelf());
    info->SetVoiceContentOption(source->GetVoiceContentOption());
    info->SetPictureOption(source->GetPictureOption());
    info->SetEnableClassification(source->GetEnableClassification());
    info->SetNeedSilentReplayOnSubscribe(source->GetNeedSilentReplayOnSubscribe());
    info->SetPriorityStrategy(source->GetPriorityStrategy());
    return info;
}

RemainingFilterResult BuildRemainingSubscribeInfo(const sptr<NotificationSubscribeInfo> &current,
    const sptr<NotificationSubscribeInfo> &removed, sptr<NotificationSubscribeInfo> &remaining)
{
    if (IsSubscribeAll(current)) {
        return RemainingFilterResult::UNSUPPORTED;
    }

    std::vector<std::string> appNames = RemoveValues(current->GetAppNames(), removed->GetAppNames());
    std::vector<int32_t> appUids = RemoveValues(current->GetAppUids(), removed->GetAppUids());
    if (appNames.empty() && appUids.empty()) {
        return RemainingFilterResult::EMPTY;
    }
    remaining = CopySubscribeInfo(current, appNames, appUids);
    return remaining == nullptr ? RemainingFilterResult::FAILED : RemainingFilterResult::UPDATED;
}

bool IsRetryableResubscribeError(ErrCode errCode)
{
    static constexpr ErrCode RETRYABLE_ERRORS[] = {
        ERR_ANS_INNER_SERVICE_NOT_READY,
        ERR_ANS_INNER_SERVICE_NOT_CONNECTED,
        ERR_ANS_INNER_TRANSACT_FAILED,
        ERR_ANS_INNER_REMOTE_DEAD,
        ERR_ANS_INNER_NO_MEMORY,
        ERR_ANS_INNER_TASK_ERR,
    };
    return std::find(std::begin(RETRYABLE_ERRORS), std::end(RETRYABLE_ERRORS), errCode) !=
        std::end(RETRYABLE_ERRORS);
}

ffrt::queue &GetResubscribeRetryQueue()
{
    static ffrt::queue queue("AnsResubscribeRetry");
    return queue;
}
}  // namespace

void AnsNotification::AddSubscriptionRecord(const sptr<IAnsSubscriber> &stub,
    const sptr<NotificationSubscribeInfo> &subscribeInfo, bool isSelf, bool isV26, uint32_t subscribedFlags)
{
    if (stub == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(subscriberMutex_);
        auto item = std::find_if(subscriptionRecords_.begin(), subscriptionRecords_.end(),
            [&stub](const auto &record) { return record.first.promote() == stub; });
        if (item != subscriptionRecords_.end()) {
            item->second.subscribeInfo = subscribeInfo;
            item->second.isSelf = isSelf;
            item->second.isV26 = isV26;
            item->second.subscribedFlags = subscribedFlags;
        } else {
            SubscriptionRecord record;
            record.subscribeInfo = subscribeInfo;
            record.isSelf = isSelf;
            record.isV26 = isV26;
            record.subscribedFlags = subscribedFlags;
            subscriptionRecords_.emplace_back(stub, record);
        }
    }
    DelayedSingleton<AnsManagerDeathRecipient>::GetInstance()->SubscribeSAManager();
}

void AnsNotification::AddLocalLiveViewSubscriptionRecord(const sptr<IAnsSubscriberLocalLiveView> &stub,
    bool isNative)
{
    if (stub == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(subscriberMutex_);
        localLiveViewSubscriptionRecords_.erase(
            std::remove_if(localLiveViewSubscriptionRecords_.begin(), localLiveViewSubscriptionRecords_.end(),
                [](const auto &record) { return record.first.promote() == nullptr; }),
            localLiveViewSubscriptionRecords_.end());
        auto item = std::find_if(localLiveViewSubscriptionRecords_.begin(),
            localLiveViewSubscriptionRecords_.end(),
            [&stub](const auto &record) { return record.first.promote() == stub; });
        if (item != localLiveViewSubscriptionRecords_.end()) {
            item->second.isNative = isNative;
        } else {
            LocalLiveViewSubscriptionRecord record;
            record.isNative = isNative;
            localLiveViewSubscriptionRecords_.emplace_back(stub, record);
        }
    }
    DelayedSingleton<AnsManagerDeathRecipient>::GetInstance()->SubscribeSAManager();
}

void AnsNotification::RemoveSubscriptionRecord(const sptr<IAnsSubscriber> &stub)
{
    if (stub == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    RemoveSubscriptionRecordLocked(stub);
}

void AnsNotification::RemoveSubscriptionRecordLocked(const sptr<IAnsSubscriber> &stub)
{
    // caller must hold subscriberMutex_
    for (auto it = subscriptionRecords_.begin(); it != subscriptionRecords_.end(); ++it) {
        if (it->first.promote() == stub) {
            subscriptionRecords_.erase(it);
            return;
        }
    }
}

AnsNotification::ReplayRecordUpdateResult AnsNotification::UpdateSubscriptionRecordAfterUnsubscribe(
    const sptr<IAnsSubscriber> &stub, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    if (stub == nullptr) {
        return ReplayRecordUpdateResult::NOT_FOUND;
    }
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    return UpdateSubscriptionRecordAfterUnsubscribeLocked(stub, subscribeInfo);
}

AnsNotification::ReplayRecordUpdateResult AnsNotification::UpdateSubscriptionRecordAfterUnsubscribeLocked(
    const sptr<IAnsSubscriber> &stub, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    // caller must hold subscriberMutex_
    if (stub == nullptr) {
        return ReplayRecordUpdateResult::NOT_FOUND;
    }
    for (auto it = subscriptionRecords_.begin(); it != subscriptionRecords_.end(); ++it) {
        if (it->first.promote() != stub) {
            continue;
        }
        if (subscribeInfo == nullptr) {
            subscriptionRecords_.erase(it);
            return ReplayRecordUpdateResult::REMOVED;
        }
        if (it->second.subscribeInfo == nullptr) {
            ANS_LOGW("Partial unsubscribe ignored for subscribe-all replay record");
            return ReplayRecordUpdateResult::KEPT;
        }
        sptr<NotificationSubscribeInfo> remaining;
        RemainingFilterResult result =
            BuildRemainingSubscribeInfo(it->second.subscribeInfo, subscribeInfo, remaining);
        if (result == RemainingFilterResult::UNSUPPORTED) {
            ANS_LOGW("Partial unsubscribe cannot be represented with the current replay record");
            return ReplayRecordUpdateResult::KEPT;
        }
        if (result == RemainingFilterResult::FAILED) {
            ANS_LOGE("Failed to build remaining subscription filter, drop replay record");
            subscriptionRecords_.erase(it);
            return ReplayRecordUpdateResult::FAILED;
        }
        if (result == RemainingFilterResult::EMPTY) {
            subscriptionRecords_.erase(it);
            return ReplayRecordUpdateResult::REMOVED;
        }
        it->second.subscribeInfo = remaining;
        return ReplayRecordUpdateResult::KEPT;
    }
    return ReplayRecordUpdateResult::NOT_FOUND;
}

void AnsNotification::UpdateSubscriberAfterUnsubscribeLocked(const sptr<IAnsSubscriber> &stub,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    if (UpdateSubscriptionRecordAfterUnsubscribeLocked(stub, subscribeInfo) ==
        ReplayRecordUpdateResult::KEPT) {
        return;
    }
    auto subscriber = std::find_if(subscribers_.begin(), subscribers_.end(),
        [&stub](const auto &item) { return item.second->AsObject() == stub->AsObject(); });
    if (subscriber != subscribers_.end()) {
        subscribers_.erase(subscriber);
    }
}

void AnsNotification::CollectReSubscribeRecords(NormalReplayRecords &normalRecords,
    LocalLiveViewReplayRecords &liveViewRecords)
{
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    for (auto it = subscriptionRecords_.begin(); it != subscriptionRecords_.end();) {
        sptr<IAnsSubscriber> stub = it->first.promote();
        if (stub == nullptr) {
            it = subscriptionRecords_.erase(it);
            continue;
        }
        normalRecords.emplace_back(stub, it->second);
        ++it;
    }
    for (auto it = localLiveViewSubscriptionRecords_.begin();
        it != localLiveViewSubscriptionRecords_.end();) {
        sptr<IAnsSubscriberLocalLiveView> stub = it->first.promote();
        if (stub == nullptr) {
            it = localLiveViewSubscriptionRecords_.erase(it);
            continue;
        }
        liveViewRecords.emplace_back(stub, it->second);
        ++it;
    }
}

void AnsNotification::CollectBadgeQueryListeners(std::vector<sptr<BadgeQueryListener>> &listeners)
{
    std::lock_guard<std::mutex> lock(badgeQueryMutex_);
    for (const auto &item : badgeQueryCallbacks_) {
        if (item.second != nullptr) {
            listeners.emplace_back(item.second);
        }
    }
}

ErrCode AnsNotification::ReSubscribeNormalRecord(const sptr<IAnsManager> &proxy,
    const sptr<IAnsSubscriber> &stub, const SubscriptionRecord &record)
{
    if (record.isV26) {
        return record.subscribeInfo == nullptr ?
            proxy->SubscribeNotification(stub, record.subscribedFlags) :
            proxy->SubscribeNotification(stub, record.subscribeInfo, record.subscribedFlags);
    }
    if (record.isSelf) {
        return proxy->SubscribeSelf(stub, record.subscribedFlags);
    }
    return record.subscribeInfo == nullptr ?
        proxy->Subscribe(stub, record.subscribedFlags) :
        proxy->Subscribe(stub, record.subscribeInfo, record.subscribedFlags);
}

void AnsNotification::ReSubscribeBadgeQueryCallbacks(const sptr<IAnsManager> &proxy,
    const std::vector<sptr<BadgeQueryListener>> &listeners, size_t &successCount, size_t &failedCount,
    bool &retryNeeded)
{
    for (const auto &listener : listeners) {
        ErrCode ret = proxy->RegisterBadgeQueryCallback(listener);
        if (ret == ERR_OK) {
            ++successCount;
            continue;
        }
        ++failedCount;
        retryNeeded = retryNeeded || IsRetryableResubscribeError(ret);
        ANS_LOGE("ReSubscribe badge query callback failed, ret=%{public}d", ret);
    }
}

bool AnsNotification::ReSubscribeNotificationsInternal()
{
    NormalReplayRecords normalRecords;
    LocalLiveViewReplayRecords liveViewRecords;
    CollectReSubscribeRecords(normalRecords, liveViewRecords);
    std::vector<sptr<BadgeQueryListener>> badgeListeners;
    CollectBadgeQueryListeners(badgeListeners);
    if (normalRecords.empty() && liveViewRecords.empty() && badgeListeners.empty()) {
        return false;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (proxy == nullptr) {
        ANS_LOGW("ReSubscribe skipped: ans manager proxy unavailable, normal=%{public}zu, liveView=%{public}zu",
            normalRecords.size(), liveViewRecords.size());
        return true;
    }

    bool retryNeeded = false;
    size_t successCount = 0;
    size_t failedCount = 0;
    for (const auto &item : normalRecords) {
        ErrCode ret = ReSubscribeNormalRecord(proxy, item.first, item.second);
        if (ret == ERR_OK) {
            ++successCount;
            continue;
        }
        ++failedCount;
        retryNeeded = retryNeeded || IsRetryableResubscribeError(ret);
        auto filterSize = GetSubscribeFilterSize(item.second.subscribeInfo);
        ANS_LOGE("ReSubscribe failed, type=%{public}s, appNames=%{public}zu, appUids=%{public}zu, ret=%{public}d",
            item.second.isV26 ? "v26" : (item.second.isSelf ? "self" : "normal"), filterSize.first,
            filterSize.second, ret);
    }
    for (const auto &item : liveViewRecords) {
        ErrCode ret = proxy->SubscribeLocalLiveView(item.first, item.second.isNative);
        if (ret == ERR_OK) {
            ++successCount;
            continue;
        }
        ++failedCount;
        retryNeeded = retryNeeded || IsRetryableResubscribeError(ret);
        ANS_LOGE("ReSubscribe local live view failed, ret=%{public}d", ret);
    }
    ReSubscribeBadgeQueryCallbacks(proxy, badgeListeners, successCount, failedCount, retryNeeded);
    // Push callbacks are intentionally not replayed here: after an ANS restart the push service
    // actively re-registers its own callback.
    ANS_LOGI("ReSubscribe finished, success=%{public}zu, failed=%{public}zu, retryNeeded=%{public}d",
        successCount, failedCount, retryNeeded);
    return retryNeeded;
}

void AnsNotification::ReSubscribeNotifications()
{
    if (!ReSubscribeNotificationsInternal()) {
        return;
    }
    bool expected = false;
    if (!reSubscribeRetryScheduled_.compare_exchange_strong(expected, true)) {
        return;
    }
    ScheduleReSubscribeRetry(1, reSubscribeRetryEpoch_.load());
}

bool AnsNotification::HandleReSubscribeRetry(uint32_t retryAttempt, uint64_t retryEpoch)
{
    if (reSubscribeRetryEpoch_.load() != retryEpoch) {
        // Only the task that still owns the scheduled epoch may clear the flag.
        if (reSubscribeRetryScheduledEpoch_.load() == retryEpoch) {
            reSubscribeRetryScheduled_.store(false);
        }
        return false;
    }
    if (!ReSubscribeNotificationsInternal()) {
        reSubscribeRetryScheduled_.store(false);
        return false;
    }
    if (retryAttempt >= RESUBSCRIBE_MAX_RETRY_TIMES) {
        NormalReplayRecords normalRecords;
        LocalLiveViewReplayRecords liveViewRecords;
        CollectReSubscribeRecords(normalRecords, liveViewRecords);
        ANS_LOGE("ReSubscribe retry exhausted, attempt=%{public}u, pendingNormal=%{public}zu, "
            "pendingLiveView=%{public}zu", retryAttempt, normalRecords.size(), liveViewRecords.size());
        reSubscribeRetryScheduled_.store(false);
        return false;
    }
    return true;
}

uint32_t AnsNotification::GetReSubscribeRetryDelayMs(uint32_t retryAttempt)
{
    if (retryAttempt == 0) {
        return 0;
    }
    uint64_t delay = static_cast<uint64_t>(RESUBSCRIBE_RETRY_BASE_INTERVAL_MS) << (retryAttempt - 1);
    return static_cast<uint32_t>(std::min<uint64_t>(delay, RESUBSCRIBE_RETRY_MAX_INTERVAL_MS));
}

void AnsNotification::ScheduleReSubscribeRetry(uint32_t retryAttempt, uint64_t retryEpoch)
{
    if (reSubscribeRetryEpoch_.load() != retryEpoch) {
        // Stale chain from a previous service life: keep the fresh chain bookkeeping untouched.
        ANS_LOGD("Skip scheduling stale reSubscribe retry, attempt=%{public}u", retryAttempt);
        return;
    }
    std::shared_ptr<AnsNotification> instance = GetInstance();
    reSubscribeRetryScheduledEpoch_.store(retryEpoch);
    GetResubscribeRetryQueue().submit([instance, retryAttempt, retryEpoch]() {
        ffrt::this_task::sleep_for(std::chrono::milliseconds(GetReSubscribeRetryDelayMs(retryAttempt)));
        if (instance->HandleReSubscribeRetry(retryAttempt, retryEpoch)) {
            instance->ScheduleReSubscribeRetry(retryAttempt + 1, retryEpoch);
        }
    });
}

void AnsNotification::InvalidateReSubscribeRetry()
{
    // Invalidate the in-flight chain and release the slot so a new service start can retry at once.
    reSubscribeRetryEpoch_.fetch_add(1);
    reSubscribeRetryScheduled_.store(false);
    ANS_LOGD("ReSubscribe retry invalidated, epoch=%{public}llu",
        static_cast<unsigned long long>(reSubscribeRetryEpoch_.load()));
}
}  // namespace Notification
}  // namespace OHOS
