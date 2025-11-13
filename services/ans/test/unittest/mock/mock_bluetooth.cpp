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

#include "bluetooth_hfp_ag.h"
#include "bluetooth_remote_device.h"
#include "mock_bluetooth.h"

namespace OHOS {
namespace Notification {

namespace {
bool g_isMockHandsFreeAudioGatewayGetDeviceStateEnabled = false;
bool g_isMockBluetoothRemoteDeviceGetPairStateEnabled = false;
}

void MockHandsFreeAudioGatewayGetDeviceStateEnabled(bool enabled)
{
    g_isMockHandsFreeAudioGatewayGetDeviceStateEnabled = enabled;
}

void MockBluetoothRemoteDeviceGetPairStateEnabled(bool enabled)
{
    g_isMockBluetoothRemoteDeviceGetPairStateEnabled = enabled;
}
}

namespace Bluetooth {
int32_t HandsFreeAudioGateway::GetDeviceState(const BluetoothRemoteDevice &device, int32_t &state)
{
    state = static_cast<int32_t>(Notification::g_isMockHandsFreeAudioGatewayGetDeviceStateEnabled ?
        Bluetooth::BTConnectState::CONNECTED : Bluetooth::BTConnectState::DISCONNECTED);
    return 0;
}

int BluetoothRemoteDevice::GetPairState(int &pairState) const
{
    pairState = static_cast<int32_t>(Notification::g_isMockBluetoothRemoteDeviceGetPairStateEnabled ?
        Bluetooth::PAIR_PAIRED : OHOS::Bluetooth::PAIR_NONE);
    return 0;
}
}
}