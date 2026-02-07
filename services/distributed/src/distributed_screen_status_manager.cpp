/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "distributed_screen_status_manager.h"

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "device_manager.h"
#include "distributed_preferences.h"
#include "distributed_data_define.h"

namespace OHOS {
namespace Notification {
namespace {
const std::string APP_ID = "notification_service";
const std::string STORE_ID = "distributed_screen_status";
const std::string DELIMITER = "|";
const std::string SCREEN_STATUS_LABEL = "screen_status";
const std::string SCREEN_STATUS_VALUE_ON = "on";
const std::string SCREEN_STATUS_VALUE_OFF = "off";
constexpr char KV_STORE_PATH[] = "/data/service/el1/public/database/notification_service";
} // namespace

DistributedScreenStatusManager::DistributedScreenStatusManager() : DistributedFlowControl()
{
    DistributedDeviceCallback::IDeviceChange callback = {
        .OnConnected = std::bind(&DistributedScreenStatusManager::OnDeviceConnected, this, std::placeholders::_1),
        .OnDisconnected = std::bind(&DistributedScreenStatusManager::OnDeviceDisconnected, this, std::placeholders::_1),
    };
    deviceCb_ = std::make_shared<DistributedDeviceCallback>(callback);
    GetKvDataManager();
}

DistributedScreenStatusManager::~DistributedScreenStatusManager()
{}

void DistributedScreenStatusManager::OnDeviceConnected(const std::string &deviceId)
{
    ANS_LOGD("deviceId:%{public}s", StringAnonymous(deviceId).c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    CheckKvStore();
}

void DistributedScreenStatusManager::OnDeviceDisconnected(const std::string &deviceId)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!CheckKvDataManager()) {
        return;
    }

    std::vector<DistributedHardware::DmDeviceInfo> devInfoList;
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList(APP_ID, "", devInfoList);
    if (ret != ERR_OK) {
        ANS_LOGE("Get trust device list failed ret = %{public}d", ret);
        kvDataManager_.reset();
        return;
    }

    if (!devInfoList.empty()) {
        return;
    }

    kvStore_.reset();

    DistributedKv::AppId appId = {.appId = APP_ID};
    DistributedKv::StoreId storeId = {.storeId = STORE_ID};
    kvDataManager_->DeleteKvStore(appId, storeId, KV_STORE_PATH);

    if (!CheckKvStore()) {
        return;
    }

    SetLocalScreenStatus(localScreenOn_);
}

void DistributedScreenStatusManager::GetKvDataManager()
{
    initCallback_ = std::make_shared<DeviceInitCallBack>();
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(APP_ID + STORE_ID, initCallback_);
    if (ret != 0) {
        ANS_LOGE("init device manager failed, ret:%{public}d", ret);
        return;
    }
    ret = DistributedHardware::DeviceManager::GetInstance().RegisterDevStateCallback(APP_ID + STORE_ID, "", deviceCb_);
    if (ret != 0) {
        ANS_LOGD("register devStateCallback failed, ret:%{public}d", ret);
        return;
    }

    kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    KvManagerFlowControlClear();
}

void DistributedScreenStatusManager::DeviceInitCallBack::OnRemoteDied()
{
    ANS_LOGD("called");
}

bool DistributedScreenStatusManager::CheckKvDataManager()
{
    if (kvDataManager_ == nullptr) {
        GetKvDataManager();
    }
    if (kvDataManager_ == nullptr) {
        ANS_LOGE("null kvDataManager");
        return false;
    }
    return true;
}

void DistributedScreenStatusManager::GetKvStore()
{
    bool enable = false;
    DistributedPreferences::GetInstance()->GetDistributedEnable(enable);
    if (!enable) {
        ANS_LOGI("DistributedEnable is false, no need to create db.");
        return;
    }

    if (!CheckKvDataManager()) {
        return;
    }
    DistributedKv::Options options = {
        .createIfMissing = true,
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
        ANS_LOGE("kvDataManager GetSingleKvStore failed ret = 0x%{public}x", status);
        kvStore_.reset();
        DistributedHardware::DeviceManager::GetInstance().UnRegisterDevStateCallback(APP_ID + STORE_ID);
        kvDataManager_.reset();
        return;
    }

    KvStoreFlowControlClear();
}

bool DistributedScreenStatusManager::CheckKvStore()
{
    if (kvStore_ == nullptr) {
        GetKvStore();
    }
    if (kvStore_ == nullptr) {
        ANS_LOGE("null kvStore");
        return false;
    }
    return true;
}

std::string DistributedScreenStatusManager::GenerateDistributedKey(const std::string &deviceId)
{
    return deviceId + DELIMITER + SCREEN_STATUS_LABEL;
}

ErrCode DistributedScreenStatusManager::CheckRemoteDevicesIsUsing(bool &isUsing)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!CheckKvDataManager() || kvStore_ == nullptr) {
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    if (!KvManagerFlowControl() || !KvStoreFlowControl()) {
        ANS_LOGE("flow control.");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    std::vector<DistributedHardware::DmDeviceInfo> devInfoList;
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList(APP_ID, "", devInfoList);
    if (ret != ERR_OK) {
        ANS_LOGE("Get trust device list failed ret = %{public}d", ret);
        kvDataManager_.reset();
        return ERR_ANS_DISTRIBUTED_GET_INFO_FAILED;
    }

    DistributedKv::Key prefixKey("");
    std::vector<DistributedKv::Entry> entries;
    DistributedKv::Status status = kvStore_->GetEntries(prefixKey, entries);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("kvStore GetEntries() failed ret = 0x%{public}x", status);
        kvStore_.reset();
        return ERR_ANS_DISTRIBUTED_GET_INFO_FAILED;
    }

    for (auto entry : entries) {
        std::string key = entry.key.ToString();
        std::string deviceId = key.substr(0, key.find_first_of(DELIMITER));
        ANS_LOGD("value:%{public}s", entry.value.ToString().c_str());
        for (auto devInfo : devInfoList) {
            if (strcmp(devInfo.deviceId, deviceId.c_str()) == 0) {
                isUsing = isUsing || (entry.value.ToString() == SCREEN_STATUS_VALUE_ON);
                break;
            }
        }
        if (isUsing) {
            break;
        }
    }

    ANS_LOGI("%{public}s, isUsing:%{public}s", __FUNCTION__, isUsing ? "true" : "false");
    return ERR_OK;
}

ErrCode DistributedScreenStatusManager::SetLocalScreenStatus(bool screenOn)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    ANS_LOGD("called, screenOn:%{public}s", screenOn ? "true" : "false");
    localScreenOn_ = screenOn;
    if (kvStore_ == nullptr) {
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    if (!KvManagerFlowControl() || !KvStoreFlowControl()) {
        ANS_LOGE("flow control.");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    DistributedHardware::DmDeviceInfo localDevice;
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(APP_ID, localDevice);
    if (ret != ERR_OK) {
        ANS_LOGE("Get trust local device info failed ret = %{public}d", ret);
        return ERR_ANS_DISTRIBUTED_GET_INFO_FAILED;
    }

    DistributedKv::Key kvStoreKey = GenerateDistributedKey(localDevice.deviceId);
    DistributedKv::Value kvStoreValue = screenOn ? SCREEN_STATUS_VALUE_ON : SCREEN_STATUS_VALUE_OFF;
    DistributedKv::Status status = kvStore_->Put(kvStoreKey, kvStoreValue);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("kvStore Put() failed ret = 0x%{public}x", status);
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
