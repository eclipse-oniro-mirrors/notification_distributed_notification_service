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

#include "extension_service_connection_service.h"

namespace OHOS {
namespace Notification {

ExtensionServiceConnectionService& ExtensionServiceConnectionService::GetInstance()
{
    static ExtensionServiceConnectionService ExtensionServiceConnectionService;
    return ExtensionServiceConnectionService;
}

void ExtensionServiceConnectionService::NotifyOnReceiveMessage(
    const std::shared_ptr<ExtensionSubscriberInfo> subscriberInfo,
    const sptr<NotificationRequest> notificationRequest)
{
    auto connection = GetConnection(subscriberInfo);
    if (connection == nullptr) {
        ANS_LOGE("null connection");
        return;
    }
    connection->NotifyOnReceiveMessage(notificationRequest);
}

void ExtensionServiceConnectionService::NotifyOnCancelMessages(
    const std::shared_ptr<ExtensionSubscriberInfo> subscriberInfo,
    const std::shared_ptr<std::vector<std::string>> hashCodes)
{
    auto connection = GetConnection(subscriberInfo);
    if (connection == nullptr) {
        ANS_LOGE("null connection");
        return;
    }
    connection->NotifyOnCancelMessages(hashCodes);
}

void ExtensionServiceConnectionService::CloseConnection(const ExtensionSubscriberInfo& subscriberInfo)
{
    std::string connectionKey = subscriberInfo.GetKey();
    ANS_LOGD("close connection: %{public}s", connectionKey.c_str());
    bool needNotify = false;
    do {
        std::lock_guard<ffrt::recursive_mutex> lock(mapLock_);
        auto iter = connectionMap_.find(connectionKey);
        if (iter == connectionMap_.end()) {
            ANS_LOGE("connection not found");
            needNotify = connectionMap_.empty();
            break;
        }
        if (iter->second == nullptr) {
            ANS_LOGE("null connection");
            connectionMap_.erase(iter);
            needNotify = connectionMap_.empty();
            break;
        }
        iter->second->Close();
    } while (false);

    if (needNotify && onAllConnectionsClosed_) {
        onAllConnectionsClosed_();
    }
}

void ExtensionServiceConnectionService::RemoveConnection(const ExtensionSubscriberInfo& subscriberInfo)
{
    std::string connectionKey = subscriberInfo.GetKey();
    ANS_LOGD("remove connection: %{public}s", connectionKey.c_str());
    bool needNotify = false;
    {
        std::lock_guard<ffrt::recursive_mutex> lock(mapLock_);
        auto iter = connectionMap_.find(connectionKey);
        if (iter != connectionMap_.end()) {
            connectionMap_.erase(iter);
        }
        needNotify = connectionMap_.empty();
    }
    if (needNotify && onAllConnectionsClosed_) {
        onAllConnectionsClosed_();
    }
}

sptr<ExtensionServiceConnection> ExtensionServiceConnectionService::GetConnection(
    const std::shared_ptr<ExtensionSubscriberInfo> subscriberInfo)
{
    if (subscriberInfo == nullptr) {
        ANS_LOGE("null subscriberInfo");
        return nullptr;
    }
    std::lock_guard<ffrt::recursive_mutex> lock(mapLock_);
    std::string connectionKey = subscriberInfo->GetKey();
    sptr<ExtensionServiceConnection> connection = nullptr;
    auto iter = connectionMap_.find(connectionKey);
    if (iter == connectionMap_.end()) {
        ANS_LOGD("create connection: %{public}s", connectionKey.c_str());
        connection = new (std::nothrow) ExtensionServiceConnection(
            *subscriberInfo, [this](const ExtensionSubscriberInfo& info) { RemoveConnection(info); });
        if (connection == nullptr) {
            ANS_LOGE("new connection failed: %{public}s", connectionKey.c_str());
        } else {
            connectionMap_[connectionKey] = connection;
        }
    } else {
        ANS_LOGD("found connection: %{public}s", connectionKey.c_str());
        connection = iter->second;
    }

    return connection;
}
}
}
