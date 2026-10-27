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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_NOTIFICATION_CLASSIFICATION_MGR_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_NOTIFICATION_CLASSIFICATION_MGR_H

#include <functional>
#include <set>
#include <string>
#include <unordered_map>

#include "ffrt.h"
#include "notification_classification.h"
#include "refbase.h"

namespace OHOS {
namespace Notification {
class NotificationClassificationMgr {
public:
    NotificationClassificationMgr(const NotificationClassificationMgr&) = delete;
    NotificationClassificationMgr& operator=(const NotificationClassificationMgr&) = delete;

    static NotificationClassificationMgr& GetInstance();

    /**
     * @brief Lands one tagging round into the cache by dimension.
     *
     * A dimension set by the round overwrites the cached one, an unset dimension
     * keeps the cached value; a null round clears the entry. The entry count is
     * bounded by MAX_ACTIVE_NUM: a new key is rejected (returns null, cache
     * untouched) once the cache is full — which in practice means orphaned entries,
     * because a live notification being evicted frees its entry through the removal
     * hooks. Every rejection fires the sweep listener (outside any lock) and the
     * first one is reported once through the SCENE_30 analytics event.
     *
     * @param key Indicates the notification key.
     * @param classification Indicates the tagging round, may be null (clears).
     * @return Returns the landed entry; null for a null round, a rejected new
     *         key at capacity, or a landing copy allocation failure.
     */
    sptr<NotificationClassification> AddOrUpdate(
        const std::string& key, const sptr<NotificationClassification>& classification);

    /**
     * @brief Registers the capacity sweep listener, called (outside any lock) each
     *        time a full cache rejects a new key; the owner reconciles the cache
     *        against the live notifications. Must be set before concurrent use.
     *
     * @param listener Indicates the sweep trigger.
     */
    void SetSweepListener(const std::function<void()>& listener);

    bool Remove(const std::string& key);

    /**
     * @brief Removes every entry whose key is not in liveKeys (orphan sweep).
     *
     * @param liveKeys Indicates the keys of the live notifications.
     */
    void RetainOnly(const std::set<std::string>& liveKeys);

    sptr<NotificationClassification> Get(const std::string& key) const;

    bool Exists(const std::string& key) const;

    size_t Size() const;

    void Clear();

private:
    NotificationClassificationMgr() = default;
    ~NotificationClassificationMgr() = default;

private:
    mutable ffrt::mutex mutex_;
    std::unordered_map<std::string, sptr<NotificationClassification>> map_;
    std::function<void()> sweepListener_;
    bool capacityAlerted_ {false};
};
} // namespace Notification
} // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_NOTIFICATION_CLASSIFICATION_MGR_H