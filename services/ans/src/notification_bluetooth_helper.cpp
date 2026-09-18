/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "notification_bluetooth_helper.h"

#include "advanced_notification_service.h"
#include "aes_gcm_helper.h"
#include "ans_log_wrapper.h"
#include "distributed_data_define.h"

namespace OHOS {
namespace Notification {
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
void BluetoothAccessObserver::OnStateChanged(const int transport, const int status)
{
    ANS_LOGI("Bluetooth state changed: transport: %{public}d, status: %{public}d", transport, status);
    AdvancedNotificationService::GetInstance()->OnBluetoothStateChanged(status);
}

void BluetoothPairedDeviceObserver::OnPairStatusChanged(const OHOS::Bluetooth::BluetoothRemoteDevice& device,
    int status, int cause)
{
    ANS_LOGI("Bluetooth paired device status changed: status: %{public}d", status);
    AdvancedNotificationService::GetInstance()->OnBluetoothPairedStatusChanged(device, status);
}
#endif
NotificationBluetoothHelper& NotificationBluetoothHelper::GetInstance()
{
    static NotificationBluetoothHelper notificationBluetoothHelper;
    return notificationBluetoothHelper;
}
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
void NotificationBluetoothHelper::RegisterBluetoothAccessObserver()
{
    if (bluetoothAccessObserver_ == nullptr) {
        bluetoothAccessObserver_ = std::make_shared<BluetoothAccessObserver>();
    }
    
    if (isBluetoothObserverRegistered_.load()) {
        return;
    }

    isBluetoothObserverRegistered_.store(true);
    Bluetooth::BluetoothHost::GetDefaultHost().RegisterObserver(bluetoothAccessObserver_);
}

void NotificationBluetoothHelper::RegisterBluetoothPairedDeviceObserver()
{
    if (bluetoothPairedDeviceObserver_ == nullptr) {
        bluetoothPairedDeviceObserver_ = std::make_shared<BluetoothPairedDeviceObserver>();
    }
    
    if (isBluetoothPairedDeviceObserverRegistered_.load()) {
        return;
    }

    isBluetoothPairedDeviceObserverRegistered_.store(true);
    Bluetooth::BluetoothHost::GetDefaultHost().RegisterRemoteDeviceObserver(bluetoothPairedDeviceObserver_);
}
#endif
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
bool NotificationBluetoothHelper::CheckBluetoothConditions(const std::string& addr)
{
    std::shared_ptr<OHOS::Bluetooth::BluetoothRemoteDevice> remoteDevice =
        std::make_shared<OHOS::Bluetooth::BluetoothRemoteDevice>(addr, OHOS::Bluetooth::BT_TRANSPORT_NONE);
    int32_t state = OHOS::Bluetooth::PAIR_NONE;
    remoteDevice->GetPairState(state);
    ANS_LOGI("Bluetooth device: %{public}s, paired state: %{public}d", StringAnonymous(addr).c_str(), state);
    return state == OHOS::Bluetooth::PAIR_PAIRED;
}

bool NotificationBluetoothHelper::CheckBluetoothSwitchState()
{
    Bluetooth::BluetoothState state = Bluetooth::BluetoothHost::GetDefaultHost().GetBluetoothState();
    return state == Bluetooth::BluetoothState::STATE_ON;
}
#endif
}  // namespace Notification
}  // namespace OHOS

