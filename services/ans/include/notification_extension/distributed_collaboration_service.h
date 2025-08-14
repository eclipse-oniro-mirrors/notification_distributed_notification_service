/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef NOTIFICATION_DISTRIBUTED_COLLABORATION_SERVICE_H
#define NOTIFICATION_DISTRIBUTED_COLLABORATION_SERVICE_H

#include <unordered_map>

#include "ffrt.h"
#include "notification.h"

namespace OHOS {
namespace Notification {

class DistributedCollaborationService {
public:
    void AddCollaborativeDeleteItem(const sptr<Notification>& notification);
    bool CheckCollaborativePublish(const sptr<Notification>& notification);
    static DistributedCollaborationService& GetInstance();

private:
    ffrt::mutex mapLock;
    std::unordered_map<std::string, int64_t> collaborativeDeleteMap_;
};

}
}
#endif // NOTIFICATION_DISTRIBUTED_COLLABORATION_SERVICE_H
