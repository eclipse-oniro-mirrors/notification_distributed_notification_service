/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_CONNECTION_SERVICE_H
#define DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_CONNECTION_SERVICE_H

#include "ffrt.h"

#include "extension_service_common.h"
#include "extension_service_connection.h"

namespace OHOS {
namespace Notification {
class ExtensionServiceConnectionService {
public:
    static ExtensionServiceConnectionService& GetInstance();
    void NotifyOnReceiveMessage(const std::shared_ptr<ExtensionSubscriberInfo> subscriberInfo,
        const sptr<NotificationRequest> notificationRequest);
    void NotifyOnCancelMessages(const std::shared_ptr<ExtensionSubscriberInfo> subscriberInfo,
        const std::shared_ptr<std::vector<std::string>> hashCodes);
    void CloseConnection(const ExtensionSubscriberInfo& subscriberInfo);
    void inline SetOnAllConnectionsClosed(std::function<void()> onAllConnectionsClosed)
    {
        onAllConnectionsClosed_ = onAllConnectionsClosed;
    }

private:
    void RemoveConnection(const ExtensionSubscriberInfo& subscriberInfo);
    sptr<ExtensionServiceConnection> GetConnection(
        const std::shared_ptr<ExtensionSubscriberInfo> subscriberInfo);

private:
    ffrt::recursive_mutex mapLock_;
    std::map<std::string, sptr<ExtensionServiceConnection>> connectionMap_;
    std::function<void()> onAllConnectionsClosed_;
};
}
}
#endif // DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_CONNECTION_SERVICE_H
