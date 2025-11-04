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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_BLUETOOTH_HELPER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_BLUETOOTH_HELPER_H

#include <atomic>
#include <memory>
#include <string>

#include "bluetooth_hfp_ag.h"
#include "bluetooth_host.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {

class HfpStateObserver : public OHOS::Bluetooth::HandsFreeAudioGatewayObserver {
public:
    HfpStateObserver() = default;
    ~HfpStateObserver() override = default;
    void OnConnectionStateChanged(
        const OHOS::Bluetooth::BluetoothRemoteDevice &device, int state, int cause) override;
};

class BluetoothAccessObserver : public OHOS::Bluetooth::BluetoothHostObserver {
public:
    BluetoothAccessObserver() = default;
    ~BluetoothAccessObserver() override = default;

    void OnStateChanged(const int transport, const int status) override;
    void OnDiscoveryStateChanged(int status) override {};
    void OnDiscoveryResult(const OHOS::Bluetooth::BluetoothRemoteDevice &device, int rssi,
        const std::string deviceName, int deviceClass) override {};
    void OnPairRequested(const OHOS::Bluetooth::BluetoothRemoteDevice &device) override {};
    void OnPairConfirmed(const OHOS::Bluetooth::BluetoothRemoteDevice &device, int reqType, int number) override {};
    void OnScanModeChanged(int mode) override {};
    void OnDeviceNameChanged(const std::string &deviceName) override {};
    void OnDeviceAddrChanged(const std::string &address) override {};
};

class BluetoothPairedDeviceObserver : public OHOS::Bluetooth::BluetoothRemoteDeviceObserver {
public:
    BluetoothPairedDeviceObserver() = default;
    ~BluetoothPairedDeviceObserver() override = default;

    void OnAclStateChanged(const OHOS::Bluetooth::BluetoothRemoteDevice& device, int state,
        unsigned int reason) override {};
    void OnPairStatusChanged(const OHOS::Bluetooth::BluetoothRemoteDevice& device, int status, int cause) override;
    void OnRemoteUuidChanged(const OHOS::Bluetooth::BluetoothRemoteDevice& device,
        const std::vector<OHOS::Bluetooth::ParcelUuid>& uuids) override {};
    void OnRemoteNameChanged(const OHOS::Bluetooth::BluetoothRemoteDevice& device,
        const std::string& deviceName) override {};
    void OnRemoteAliasChanged(const OHOS::Bluetooth::BluetoothRemoteDevice& device,
        const std::string& alias) override {};
    void OnRemoteCodChanged(const OHOS::Bluetooth::BluetoothRemoteDevice& device,
        const OHOS::Bluetooth::BluetoothDeviceClass& cod) override {};
    void OnRemoteBatteryLevelChanged(const OHOS::Bluetooth::BluetoothRemoteDevice& device,
        int batteryLevel) override {};
    void OnReadRemoteRssiEvent(const OHOS::Bluetooth::BluetoothRemoteDevice& device, int rssi,
        int status) override {};
    void OnRemoteBatteryChanged(const OHOS::Bluetooth::BluetoothRemoteDevice& device,
        const OHOS::Bluetooth::DeviceBatteryInfo& batteryInfo) override {};
};

class NotificationBluetoothHelper {
public:
    /**
     * @brief Get the singleton instance of NotificationBluetoothHelper.
     *
     * @return Returns the singleton instance.
     */
    static NotificationBluetoothHelper& GetInstance();

    /**
     * @brief Register HFP observer.
     */
    void RegisterHfpObserver();

    /**
     * @brief Register Bluetooth access observer.
     */
    void RegisterBluetoothAccessObserver();

    /**
     * @brief Register Bluetooth paired device observer.
     */
    void RegisterBluetoothPairedDeviceObserver();

    /**
     * @brief Check if HFP device is connected.
     *
     * @param bluetoothAddress The bluetooth address.
     * @return Returns true if connected, false otherwise.
     */
    bool CheckHfpState(const std::string &bluetoothAddress);

    /**
     * @brief Check Bluetooth connection-related conditions for the given address.
     *
     * @param addr The Bluetooth address to check.
     * @return Returns true if the Bluetooth conditions are met, false otherwise.
     */
    bool CheckBluetoothConditions(const std::string& addr);

    /**
     * @brief Check if Bluetooth switch is on.
     *
     * @return Returns true if Bluetooth is on, false otherwise.
     */
    bool CheckBluetoothSwitchState();

private:
    NotificationBluetoothHelper() = default;
    ~NotificationBluetoothHelper() = default;

    NotificationBluetoothHelper(const NotificationBluetoothHelper&) = delete;
    NotificationBluetoothHelper& operator=(const NotificationBluetoothHelper&) = delete;
    NotificationBluetoothHelper(NotificationBluetoothHelper&&) = delete;
    NotificationBluetoothHelper& operator=(NotificationBluetoothHelper&&) = delete;

    std::shared_ptr<HfpStateObserver> hfpObserver_ = nullptr;
    std::shared_ptr<BluetoothAccessObserver> bluetoothAccessObserver_ = nullptr;
    std::shared_ptr<BluetoothPairedDeviceObserver> bluetoothPairedDeviceObserver_ = nullptr;
    std::atomic<bool> isBluetoothObserverRegistered_ = false;
    std::atomic<bool> isHfpObserverRegistered_ = false;
    std::atomic<bool> isBluetoothPairedDeviceObserverRegistered_ = false;
};

}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_BLUETOOTH_HELPER_H

