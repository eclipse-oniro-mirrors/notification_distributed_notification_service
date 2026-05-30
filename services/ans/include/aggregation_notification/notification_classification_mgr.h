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

    void AddOrUpdate(const std::string& key, sptr<NotificationClassification> classification);

    bool Remove(const std::string& key);

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
};
} // namespace Notification
} // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_NOTIFICATION_CLASSIFICATION_MGR_H