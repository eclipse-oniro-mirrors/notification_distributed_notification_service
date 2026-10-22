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

#include "notification_classification_mgr.h"

#include <new>

#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "notification_analytics_util.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr char CLASSIFICATION_CACHE_CONTAINER_NAME[] = "classification_cache";
}

NotificationClassificationMgr& NotificationClassificationMgr::GetInstance()
{
    static NotificationClassificationMgr instance;
    return instance;
}

sptr<NotificationClassification> NotificationClassificationMgr::AddOrUpdate(
    const std::string& key, const sptr<NotificationClassification>& classification)
{
    if (classification == nullptr) {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        map_.erase(key);
        return nullptr;
    }

    bool reportCapacity = false;
    bool requestSweep = false;
    size_t currentSize = 0;
    sptr<NotificationClassification> landed = nullptr;
    std::function<void()> sweepListener = nullptr;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto it = map_.find(key);
        sptr<NotificationClassification> cached = (it != map_.end()) ? it->second : nullptr;
        if (cached == nullptr && map_.size() >= MAX_ACTIVE_NUM) {
            currentSize = map_.size();
            reportCapacity = !capacityAlerted_;
            capacityAlerted_ = true;
            requestSweep = true;
            sweepListener = sweepListener_;
        } else {
            landed = new (std::nothrow) NotificationClassification();
            if (landed != nullptr) {
                if (classification->IsClassificationSet()
                    || (cached != nullptr && cached->IsClassificationSet())) {
                    if (classification->IsClassificationSet()) {
                        landed->SetClassification(classification->GetClassification());
                        landed->SetSubClassification(classification->GetSubClassification());
                    } else {
                        landed->SetClassification(cached->GetClassification());
                        landed->SetSubClassification(cached->GetSubClassification());
                    }
                }

                if (classification->IsPriorityInfoSet()
                    || (cached != nullptr && cached->IsPriorityInfoSet())) {
                    if (classification->IsPriorityInfoSet()) {
                        landed->SetPriorityInfo(classification->GetPriorityInfo());
                    } else {
                        landed->SetPriorityInfo(cached->GetPriorityInfo());
                    }
                }

                map_[key] = landed;
            }
        }
    }

    if (reportCapacity) {
        ANS_LOGW("Classification cache reached capacity, reject new key, capacity: %{public}zu, "
            "current size: %{public}zu", MAX_ACTIVE_NUM, currentSize);
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_0);
        message.Message(std::string(CLASSIFICATION_CACHE_CONTAINER_NAME) + "_cap_"
            + std::to_string(MAX_ACTIVE_NUM) + "_size_" + std::to_string(currentSize));
        NotificationAnalyticsUtil::ReportModifyEvent(message);
    }
    if (requestSweep && sweepListener != nullptr) {
        sweepListener();
    }
    return landed;
}

void NotificationClassificationMgr::SetSweepListener(const std::function<void()>& listener)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    sweepListener_ = listener;
}

void NotificationClassificationMgr::RetainOnly(const std::set<std::string>& liveKeys)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    for (auto it = map_.begin(); it != map_.end();) {
        if (liveKeys.find(it->first) == liveKeys.end()) {
            it = map_.erase(it);
        } else {
            ++it;
        }
    }
}

bool NotificationClassificationMgr::Remove(const std::string& key)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    return map_.erase(key) > 0;
}

sptr<NotificationClassification> NotificationClassificationMgr::Get(
    const std::string& key) const
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it != map_.end()) {
        return it->second;
    }
    return nullptr;
}

bool NotificationClassificationMgr::Exists(const std::string& key) const
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    return map_.find(key) != map_.end();
}

size_t NotificationClassificationMgr::Size() const
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    return map_.size();
}

void NotificationClassificationMgr::Clear()
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    map_.clear();
}
} // namespace Notification
} // namespace OHOS
