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

void ExtensionServiceConnectionService::RemoveConnection(const ExtensionSubscriberInfo& subscriberInfo)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    std::string connectionKey(subscriberInfo.bundleName);
    connectionKey.append("_")
        .append(subscriberInfo.extensionName)
        .append("_")
        .append(std::to_string(subscriberInfo.userId));
    auto iter = connectionMap_.find(connectionKey);
    if (iter != connectionMap_.end()) {
        connectionMap_.erase(iter);
    }
}

std::shared_ptr<ExtensionServiceConnection> ExtensionServiceConnectionService::GetConnection(
    const std::shared_ptr<ExtensionSubscriberInfo> subscriberInfo)
{
    if (subscriberInfo == nullptr) {
        ANS_LOGE("null subscriberInfo");
        return nullptr;
    }
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    std::string connectionKey(subscriberInfo->bundleName);
    connectionKey.append("_")
        .append(subscriberInfo->extensionName)
        .append("_")
        .append(std::to_string(subscriberInfo->userId));
    std::shared_ptr<ExtensionServiceConnection> connection = nullptr;
    auto iter = connectionMap_.find(connectionKey);
    if (iter == connectionMap_.end()) {
        connection = std::make_shared<ExtensionServiceConnection>(*subscriberInfo);
        connectionMap_[connectionKey] = connection;
    } else {
        connection = iter->second;
    }

    return connection;
}
}
}
