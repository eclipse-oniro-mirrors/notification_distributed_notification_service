/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "distributed_notification_manager.h"

#include <vector>

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "distributed_data_define.h"

namespace OHOS {
namespace Notification {
namespace {
const std::string DELIMITER = "|";
}  // namespace

DistributedNotificationManager::DistributedNotificationManager()
{
    ANS_LOGI("constructor");
    distributedQueue_ = std::make_shared<ffrt::queue>("NotificationDistributedMgr");

    DistributedDatabaseCallback::IDatabaseChange databaseCallback = {
        .OnInsert = std::bind(&DistributedNotificationManager::OnDatabaseInsert,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnUpdate = std::bind(&DistributedNotificationManager::OnDatabaseUpdate,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnDelete = std::bind(&DistributedNotificationManager::OnDatabaseDelete,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
    };
    databaseCb_ = std::make_shared<DistributedDatabaseCallback>(databaseCallback);

    DistributedDeviceCallback::IDeviceChange deviceCallback = {
        .OnConnected = std::bind(&DistributedNotificationManager::OnDeviceConnected, this, std::placeholders::_1),
        .OnDisconnected = std::bind(&DistributedNotificationManager::OnDeviceDisconnected, this, std::placeholders::_1),
    };
    deviceCb_ = std::make_shared<DistributedDeviceCallback>(deviceCallback);
    database_ = std::make_shared<DistributedDatabase>(databaseCb_, deviceCb_);
}

DistributedNotificationManager::~DistributedNotificationManager()
{
    ANS_LOGI("deconstructor");
    std::lock_guard<ffrt::mutex> lock(callbackMutex_);
    callback_ = {};
}

void DistributedNotificationManager::ResetFfrtQueue()
{
    if (distributedQueue_ != nullptr) {
        distributedQueue_.reset();
    }
}

void DistributedNotificationManager::GenerateDistributedKey(
    const std::string &deviceId, const std::string &bundleName, const std::string &label, int32_t id, std::string &key)
{
    key = deviceId + DELIMITER + bundleName + DELIMITER + label + DELIMITER + ToString(id);
}

bool DistributedNotificationManager::GenerateLocalDistributedKey(
    const std::string &bundleName, const std::string &label, int32_t id, std::string &key)
{
    std::string deviceId;
    if (database_ == nullptr) {
        ANS_LOGE("database_ is invalid.");
        return false;
    }
    if (!database_->GetLocalDeviceId(deviceId)) {
        return false;
    }

    GenerateDistributedKey(deviceId, bundleName, label, id, key);
    return true;
}

bool DistributedNotificationManager::ResolveDistributedKey(const std::string &key, ResolveKey &resolveKey)
{
    std::size_t deviceIdPosition = 0;
    std::size_t deviceIdEndPosition = key.find(DELIMITER, deviceIdPosition);
    if (deviceIdEndPosition == std::string::npos) {
        return false;
    }
    std::size_t bundleNamePosition = deviceIdEndPosition + DELIMITER.size();
    std::size_t bundleNameEndPosition = key.find(DELIMITER, bundleNamePosition);
    if (bundleNameEndPosition == std::string::npos) {
        return false;
    }
    std::size_t labelPosition = bundleNameEndPosition + DELIMITER.size();
    std::size_t labelEndPosition = key.find_last_of(DELIMITER) - DELIMITER.size() + 1;
    if (labelEndPosition < labelPosition) {
        return false;
    }
    std::size_t idPosition = key.find_last_of(DELIMITER) + DELIMITER.size();

    resolveKey.deviceId = key.substr(deviceIdPosition, deviceIdEndPosition - deviceIdPosition);
    resolveKey.bundleName = key.substr(bundleNamePosition, bundleNameEndPosition - bundleNamePosition);
    resolveKey.label = key.substr(labelPosition, labelEndPosition - labelPosition);
    resolveKey.id = atoi(&key[idPosition]);

    return true;
}

bool DistributedNotificationManager::CheckDeviceId(const std::string &deviceId, const std::string &key)
{
    ResolveKey resolveKey;
    if (!ResolveDistributedKey(key, resolveKey)) {
        ANS_LOGE("key <%{public}s> is invalid.", key.c_str());
        return false;
    }

    return deviceId == resolveKey.deviceId;
}

void DistributedNotificationManager::OnDatabaseInsert(
    const std::string &deviceId, const std::string &key, const std::string &value)
{
    ANS_LOGD("start");
    if (distributedQueue_ == nullptr) {
        ANS_LOGE("Serial queue is nullptr.");
        return;
    }
    distributedQueue_->submit(std::bind([=]() {
        if (!CheckDeviceId(deviceId, key)) {
            ANS_LOGD("device id is distinct. deviceId:%{public}s key:%{public}s",
                StringAnonymous(deviceId).c_str(), key.c_str());
        }

        ResolveKey resolveKey;
        if (!ResolveDistributedKey(key, resolveKey)) {
            ANS_LOGE("key <%{public}s> is invalidity.", key.c_str());
            return;
        }

        sptr<NotificationRequest> request =
            NotificationJsonConverter::ConvertFromJsonString<NotificationRequest>(value);
        if (request == nullptr) {
            ANS_LOGE("convert json to request failed. key:%{public}s", key.c_str());
            return;
        }

        PublishCallback(resolveKey.deviceId, resolveKey.bundleName, request);
    }));
}

void DistributedNotificationManager::OnDatabaseUpdate(
    const std::string &deviceId, const std::string &key, const std::string &value)
{
    ANS_LOGD("start");
    if (distributedQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    ffrt::task_handle handler = distributedQueue_->submit_h(std::bind([=]() {
        if (!CheckDeviceId(deviceId, key)) {
            ANS_LOGD("device id are not the same. deviceId:%{public}s key:%{public}s",
                StringAnonymous(deviceId).c_str(), key.c_str());
        }

        ResolveKey resolveKey;
        if (!ResolveDistributedKey(key, resolveKey)) {
            ANS_LOGE("key <%{public}s> is invalid.", key.c_str());
            return;
        }

        sptr<NotificationRequest> request =
            NotificationJsonConverter::ConvertFromJsonString<NotificationRequest>(value);
        if (request == nullptr) {
            ANS_LOGE("convert json to request failed. key:%{public}s", key.c_str());
            return;
        }

        UpdateCallback(resolveKey.deviceId, resolveKey.bundleName, request);
    }));
}

void DistributedNotificationManager::OnDatabaseDelete(
    const std::string &deviceId, const std::string &key, const std::string &value)
{
    ANS_LOGD("start");
    if (distributedQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    distributedQueue_->submit(std::bind([=]() {
        if (!CheckDeviceId(deviceId, key)) {
            ANS_LOGD("device id are not the same. deviceId:%{public}s key:%{public}s",
                StringAnonymous(deviceId).c_str(), key.c_str());
        }

        ResolveKey resolveKey;
        if (!ResolveDistributedKey(key, resolveKey)) {
            ANS_LOGE("key <%{public}s> is invalid.", key.c_str());
            return;
        }

        DeleteCallback(resolveKey.deviceId, resolveKey.bundleName, resolveKey.label, resolveKey.id);
    }));
}

void DistributedNotificationManager::OnDeviceConnected(const std::string &deviceId)
{
    ANS_LOGD("start");
    if (distributedQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    distributedQueue_->submit(std::bind([=]() {
        if (database_ == nullptr) {
            ANS_LOGE("OnDeviceConnected failed: database is null");
            return;
        }
        if (!database_->OnDeviceConnected()) {
            ANS_LOGE("OnDeviceConnected failed.");
        }
    }));
}

void DistributedNotificationManager::OnDeviceDisconnected(const std::string &deviceId)
{
    ANS_LOGD("start");
    if (distributedQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    distributedQueue_->submit(std::bind([=]() {
        std::string prefixKey = deviceId + DELIMITER;
        std::vector<DistributedDatabase::Entry> entries;
        if (database_ == nullptr) {
            ANS_LOGE("database_ is invalid.");
            return;
        }
        if (!database_->GetEntriesFromDistributedDB(prefixKey, entries)) {
            ANS_LOGE("GetEntriesFromDistributedDB failed.");
            return;
        }

        for (auto index : entries) {
            ResolveKey resolveKey;
            if (!ResolveDistributedKey(index.key.ToString(), resolveKey)) {
                ANS_LOGE("key <%{public}s> is invalid.", index.key.ToString().c_str());
                continue;
            }

            DeleteCallback(resolveKey.deviceId, resolveKey.bundleName, resolveKey.label, resolveKey.id);
        }

        database_->ClearDataByDevice(deviceId);

        std::vector<DistributedDatabase::DeviceInfo> deviceList;
        if (database_->GetDeviceInfoList(deviceList) == ERR_OK && deviceList.empty()) {
            database_->RecreateDistributedDB();
        }
    }));
}

bool DistributedNotificationManager::PublishCallback(
    const std::string &deviceId, const std::string &bundleName, sptr<NotificationRequest> &request)
{
    ANS_LOGI("start");
    std::lock_guard<ffrt::mutex> lock(callbackMutex_);
    if (callback_.OnPublish) {
        callback_.OnPublish(deviceId, bundleName, request);
    }
    ANS_LOGD("end");

    return true;
}

bool DistributedNotificationManager::UpdateCallback(
    const std::string &deviceId, const std::string &bundleName, sptr<NotificationRequest> &request)
{
    ANS_LOGI("start");
    std::lock_guard<ffrt::mutex> lock(callbackMutex_);
    if (callback_.OnUpdate) {
        callback_.OnUpdate(deviceId, bundleName, request);
    }
    ANS_LOGD("end");

    return true;
}

bool DistributedNotificationManager::DeleteCallback(
    const std::string &deviceId, const std::string &bundleName, const std::string &label, int32_t id)
{
    ANS_LOGI("start");
    std::lock_guard<ffrt::mutex> lock(callbackMutex_);
    if (callback_.OnDelete) {
        callback_.OnDelete(deviceId, bundleName, label, id);
    }
    ANS_LOGD("end");

    return true;
}

ErrCode DistributedNotificationManager::Publish(
    const std::string &bundleName, const std::string &label, int32_t id, const sptr<NotificationRequest> &request)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("start");
    std::string key;
    if (!GenerateLocalDistributedKey(bundleName, label, id, key)) {
        ANS_LOGE("Failed to generate distributed key.");
        return ERR_ANS_DISTRIBUTED_GET_INFO_FAILED;
    }

    std::string value;
    if (!NotificationJsonConverter::ConvertToJsonString(request, value)) {
        ANS_LOGE("convert request to json failed. key:%{public}s", key.c_str());
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    if (database_ == nullptr) {
        ANS_LOGE("database_ is nullptr.");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    if (!database_->PutToDistributedDB(key, value)) {
        ANS_LOGE("put to distributed DB failed. key:%{public}s", key.c_str());
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    return ERR_OK;
}

ErrCode DistributedNotificationManager::Update(
    const std::string &bundleName, const std::string &label, int32_t id, const sptr<NotificationRequest> &request)
{
    ANS_LOGD("start");
    std::string key;
    if (!GenerateLocalDistributedKey(bundleName, label, id, key)) {
        ANS_LOGE("Generate distributed key failed.");
        return ERR_ANS_DISTRIBUTED_GET_INFO_FAILED;
    }

    std::string value;
    if (!NotificationJsonConverter::ConvertToJsonString(request, value)) {
        ANS_LOGE("convert request to json failed. key:%{public}s", key.c_str());
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    if (database_ == nullptr) {
        ANS_LOGE("database_ is invalid.");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    if (!database_->PutToDistributedDB(key, value)) {
        ANS_LOGE("put to distributed DB failed. key:%{public}s", key.c_str());
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    return ERR_OK;
}

ErrCode DistributedNotificationManager::Delete(const std::string &bundleName, const std::string &label, int32_t id)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("start");
    std::string key;
    if (!GenerateLocalDistributedKey(bundleName, label, id, key)) {
        ANS_LOGE("Generate distributed key failed.");
        return ERR_ANS_DISTRIBUTED_GET_INFO_FAILED;
    }

    if (database_ == nullptr) {
        ANS_LOGE("database_ is nullptr.");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    if (!database_->DeleteToDistributedDB(key)) {
        ANS_LOGE("Failed to DeleteToDistributedDB. key:%{public}s", key.c_str());
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    return ERR_OK;
}

ErrCode DistributedNotificationManager::DeleteRemoteNotification(
    const std::string &deviceId, const std::string &bundleName, const std::string &label, int32_t id)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("start");

    std::string key;
    GenerateDistributedKey(deviceId, bundleName, label, id, key);

    if (database_ == nullptr) {
        ANS_LOGE("database_ is invalid.");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    if (!database_->DeleteToDistributedDB(key)) {
        ANS_LOGE("delete to distributed DB failed. key:%{public}s", StringAnonymous(key).c_str());
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    return ERR_OK;
}

ErrCode DistributedNotificationManager::RegisterCallback(const IDistributedCallback &callback)
{
    ANS_LOGD("start");
    if (distributedQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<ffrt::mutex> lock(callbackMutex_);
    callback_ = callback;
    return ERR_OK;
}

ErrCode DistributedNotificationManager::UngegisterCallback()
{
    ANS_LOGD("start");
    std::lock_guard<ffrt::mutex> lock(callbackMutex_);
    callback_ = {};
    return ERR_OK;
}

ErrCode DistributedNotificationManager::GetCurrentDistributedNotification(
    std::vector<sptr<NotificationRequest>> &requestList)
{
    ANS_LOGD("start");
    std::string prefixKey = "";
    std::vector<DistributedDatabase::Entry> entries;
    if (database_ == nullptr) {
        ANS_LOGE("database_ is invalid.");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    if (!database_->GetEntriesFromDistributedDB(prefixKey, entries)) {
        ANS_LOGE("GetEntriesFromDistributedDB failed.");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    for (auto index : entries) {
        ResolveKey resolveKey;
        if (!ResolveDistributedKey(index.key.ToString(), resolveKey)) {
            ANS_LOGE("key <%{public}s> is invalid.", index.key.ToString().c_str());
            continue;
        }

        sptr<NotificationRequest> request =
            NotificationJsonConverter::ConvertFromJsonString<NotificationRequest>(index.value.ToString());
        if (request == nullptr) {
            ANS_LOGE("convert json to request failed. key:%{public}s", index.key.ToString().c_str());
            continue;
        }

        PublishCallback(resolveKey.deviceId, resolveKey.bundleName, request);
    }

    return ERR_OK;
}

ErrCode DistributedNotificationManager::GetLocalDeviceInfo(DistributedDatabase::DeviceInfo &deviceInfo)
{
    ANS_LOGD("start");
    if (database_ == nullptr) {
        ANS_LOGE("database_ is invalid.");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    if (!database_->GetLocalDeviceInfo(deviceInfo)) {
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    return ERR_OK;
}

ErrCode DistributedNotificationManager::OnDistributedKvStoreDeathRecipient()
{
    ANS_LOGD("start");
    database_ = std::make_shared<DistributedDatabase>(databaseCb_, deviceCb_);
    if (!database_->RecreateDistributedDB()) {
        ANS_LOGE("RecreateDistributedDB failed.");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
