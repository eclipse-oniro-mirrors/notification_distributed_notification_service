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

#include "distributed_database.h"

#include "ans_log_wrapper.h"
#include "device_manager.h"
#include "distributed_preferences.h"

namespace OHOS {
namespace Notification {
namespace {
const std::string APP_ID = "notification_service";
const std::string STORE_ID = "distributed_notification";
constexpr char KV_STORE_PATH[] = "/data/service/el1/public/database/notification_service";
}  // namespace

DistributedDatabase::DistributedDatabase(
    std::shared_ptr<DistributedDatabaseCallback> databaseCb, std::shared_ptr<DistributedDeviceCallback> deviceCb)
    : DistributedFlowControl(), databaseCb_(databaseCb), deviceCb_(deviceCb)
{
    GetKvDataManager();
}

DistributedDatabase::~DistributedDatabase()
{}

void DistributedDatabase::GetKvDataManager()
{
#ifdef DISABLE_DISTRIBUTED_NOTIFICATION_SUPPORTED
    initCallback_ = std::make_shared<DeviceInitCallBack>();
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(APP_ID + STORE_ID, initCallback_);
    if (ret != ERR_OK) {
        ANS_LOGE("init device manager failed, ret:%{public}d", ret);
        return;
    }
#else
    int32_t ret = ERR_OK;
#endif
    ret = DistributedHardware::DeviceManager::GetInstance().RegisterDevStateCallback(APP_ID + STORE_ID, "", deviceCb_);
    if (ret != ERR_OK) {
        ANS_LOGD("register devStateCallback failed, ret:%{public}d", ret);
        return;
    }

    kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    KvManagerFlowControlClear();
}

void DistributedDatabase::DeviceInitCallBack::OnRemoteDied()
{
    ANS_LOGW("DeviceInitCallBack OnRemoteDied");
}

bool DistributedDatabase::CheckKvDataManager()
{
    if (kvDataManager_ == nullptr) {
        GetKvDataManager();
    }
    if (kvDataManager_ == nullptr) {
        ANS_LOGE("kvDataManager_ is nullptr.");
        return false;
    }
    return true;
}

void DistributedDatabase::GetKvStore()
{
    if (!CheckKvDataManager()) {
        return;
    }

    bool enable = false;
    DistributedPreferences::GetInstance()->GetDistributedEnable(enable);
    if (!enable) {
        ANS_LOGI("DistributedEnable is false, no need to create db.");
        return;
    }

    DistributedKv::Options options {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .securityLevel = DistributedKv::SecurityLevel::S1,
        .area = DistributedKv::EL1,
        .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
        .baseDir = KV_STORE_PATH
    };
    DistributedKv::AppId appId = {.appId = APP_ID};
    DistributedKv::StoreId storeId = {.storeId = STORE_ID};
    DistributedKv::Status status = kvDataManager_->GetSingleKvStore(options, appId, storeId, kvStore_);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("Failed to GetSingleKvStore ret = 0x%{public}x", status);
        kvStore_.reset();
        DistributedHardware::DeviceManager::GetInstance().UnRegisterDevStateCallback(APP_ID + STORE_ID);
        kvDataManager_.reset();
        return;
    }

    if (kvStore_ != nullptr) {
        status = kvStore_->SubscribeKvStore(DistributedKv::SubscribeType::SUBSCRIBE_TYPE_REMOTE, databaseCb_);
        if (status != DistributedKv::Status::SUCCESS) {
            ANS_LOGE("kvStore SubscribeKvStore failed ret = 0x%{public}x", status);
            kvStore_.reset();
        }
    }

    KvStoreFlowControlClear();
}

bool DistributedDatabase::CheckKvStore()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (kvStore_ == nullptr) {
        GetKvStore();
    }
    if (kvStore_ == nullptr) {
        ANS_LOGE("kvStore is nullptr.");
        return false;
    }
    return true;
}

bool DistributedDatabase::OnDeviceConnected()
{
    return CheckKvStore();
}

bool DistributedDatabase::PutToDistributedDB(const std::string &key, const std::string &value)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (kvStore_ == nullptr) {
        ANS_LOGE("kvStore is null.");
        return false;
    }

    if (!KvStoreFlowControl()) {
        ANS_LOGE("KvStore flow control.");
        return false;
    }

    DistributedKv::Key kvStoreKey(key);
    DistributedKv::Value kvStoreValue(value);
    DistributedKv::Status status = kvStore_->Put(kvStoreKey, kvStoreValue);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("kvStore Put() failed ret = 0x%{public}x", status);
        return false;
    }

    return true;
}

bool DistributedDatabase::GetFromDistributedDB(const std::string &key, std::string &value)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (kvStore_ == nullptr) {
        ANS_LOGE("kvStore is nullptr.");
        return false;
    }

    if (!KvStoreFlowControl()) {
        ANS_LOGE("KvStoreFlowControl is false.");
        return false;
    }

    DistributedKv::Key kvStoreKey(key);
    DistributedKv::Value kvStoreValue;
    DistributedKv::Status status = kvStore_->Get(kvStoreKey, kvStoreValue);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("kvStore Get() failed ret = 0x%{public}x", status);
        return false;
    }

    value = kvStoreValue.ToString();

    return true;
}

bool DistributedDatabase::GetEntriesFromDistributedDB(const std::string &prefixKey, std::vector<Entry> &entries)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (kvStore_ == nullptr) {
        ANS_LOGE("kvStore_ is nullptr.");
        return false;
    }

    if (!KvStoreFlowControl()) {
        ANS_LOGE("KvStoreFlowControl is fail.");
        return false;
    }

    DistributedKv::Key kvStoreKey(prefixKey);
    DistributedKv::Status status = kvStore_->GetEntries(kvStoreKey, entries);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("kvStore GetEntries() failed ret = 0x%{public}x", status);
        return false;
    }

    return true;
}

bool DistributedDatabase::DeleteToDistributedDB(const std::string &key)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (kvStore_ == nullptr) {
        ANS_LOGE("kvStore is nullptr.");
        return false;
    }

    if (!KvStoreFlowControl()) {
        ANS_LOGE("KvStoreFlowControl is defeat.");
        return false;
    }

    DistributedKv::Key kvStoreKey(key);
    DistributedKv::Status status = kvStore_->Delete(kvStoreKey);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("kvStore Delete() failed ret = 0x%{public}x", status);
        return false;
    }

    return true;
}

bool DistributedDatabase::ClearDataByDevice(const std::string &deviceId)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (kvStore_ == nullptr) {
        ANS_LOGE("kvStore is nullptr.");
        return false;
    }

    if (!KvStoreFlowControl()) {
        ANS_LOGE("KvStore flow control.");
        return false;
    }

    DistributedKv::Status status = kvStore_->RemoveDeviceData(deviceId);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("kvStore RemoveDeviceData() failed ret = 0x%{public}x", status);
        return false;
    }

    return true;
}

bool DistributedDatabase::GetLocalDeviceId(std::string &deviceId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!CheckKvDataManager()) {
        return false;
    }

    if (KvManagerFlowControl()) {
        DistributedHardware::DmDeviceInfo deviceInfo;
        int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(APP_ID, deviceInfo);
        if (ret != ERR_OK) {
            ANS_LOGE("Get trust local device info failed ret = %{public}d", ret);
            return false;
        }
        localDeviceId_ = deviceInfo.deviceId;
    }

    if (localDeviceId_.empty()) {
        return false;
    }

    deviceId = localDeviceId_;

    return true;
}

bool DistributedDatabase::GetLocalDeviceInfo(DeviceInfo &localInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!CheckKvDataManager()) {
        return false;
    }

    if (!KvManagerFlowControl()) {
        ANS_LOGE("KvManager flow control.");
        return false;
    }

    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(APP_ID, localInfo);
    if (ret != ERR_OK) {
        ANS_LOGE("Get trust local device info failed ret = %{public}d", ret);
        return false;
    }

    return true;
}

bool DistributedDatabase::GetDeviceInfoList(std::vector<DeviceInfo> &deviceList)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!CheckKvDataManager()) {
        return false;
    }

    if (!KvManagerFlowControl()) {
        ANS_LOGE("KvManager flow control.");
        return false;
    }

    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList(APP_ID, "", deviceList);
    if (ret != ERR_OK) {
        ANS_LOGE("Get trust device list failed ret = %{public}d", ret);
        return false;
    }

    return true;
}

bool DistributedDatabase::RecreateDistributedDB()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!CheckKvDataManager()) {
        return false;
    }

    if (!KvManagerFlowControl()) {
        ANS_LOGE("KvManager flow control.");
        return false;
    }
    kvStore_.reset();
    DistributedKv::AppId appId = {.appId = APP_ID};
    DistributedKv::StoreId storeId = {.storeId = STORE_ID};
    DistributedKv::Status status = kvDataManager_->DeleteKvStore(appId, storeId, KV_STORE_PATH);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("kvDataManager DeleteKvStore() failed ret = 0x%{public}x", status);
        return false;
    }

    return true;
}
}  // namespace Notification
}  // namespace OHOS
