/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <memory>

#include <securec.h>
#include "gtest/gtest.h"
#define private public
#include "match_box.h"
#include "remove_box.h"
#include "distributed_server.h"
#include "distributed_client.h"
#include "distributed_send_adapter.h"
#include "analytics_util.h"

using namespace testing::ext;
using namespace OHOS::DistributedHardware;

namespace OHOS {
namespace Notification {
class SoftbusTest : public testing::Test {
public:
    void SetUp() override {};
    void TearDown() override {};
};

/**
 * @tc.name   : init socket server.
 * @tc.number : SoftbusTest_0100
 * @tc.desc   : test soft bus interface.
 */
HWTEST_F(SoftbusTest, SoftbusTest_0100, Function | SmallTest | Level1)
{
    // init server
    int32_t result = DistributedServer::GetInstance().InitServer("phone",
        DmDeviceType::DEVICE_TYPE_PHONE);
    EXPECT_EQ(result, 0);
    auto sockets = DistributedServer::GetInstance().serverSocket_;
    EXPECT_EQ((int32_t)sockets.size(), 1);

    // release server
    DistributedServer::GetInstance().ReleaseServer();
    sockets = DistributedServer::GetInstance().serverSocket_;
    EXPECT_EQ((int32_t)sockets.size(), 0);

    // init server
    result = DistributedServer::GetInstance().InitServer("watch",
        DmDeviceType::DEVICE_TYPE_WATCH);
    EXPECT_EQ(result, 0);
    sockets = DistributedServer::GetInstance().serverSocket_;
    EXPECT_EQ((int32_t)sockets.size(), 2);

    // receive peer bind
    char name[10] = { "name" };
    char networkId[10] = { "networkId" };
    char pkgName[10] = { "pkgName" };
    PeerSocketInfo info;
    info.name = name;
    info.networkId = networkId;
    info.pkgName = pkgName;
    DistributedServer::GetInstance().OnBind(10, info);
    DistributedServer::GetInstance().OnBind(11, info);

    char data[10] = { "0" };
    // receive peer byte
    DistributedServer::GetInstance().OnBytes(10, data, 10);
    // receive peer message
    DistributedServer::GetInstance().OnMessage(10, data, 10);

    auto peerSockets = DistributedServer::GetInstance().peerSockets_;
    EXPECT_EQ((int32_t)peerSockets.size(), 2);

    // receive peer shotdwon
    DistributedServer::GetInstance().OnShutdown(11, ShutdownReason::SHUTDOWN_REASON_PEER);
    peerSockets = DistributedServer::GetInstance().peerSockets_;
    EXPECT_EQ((int32_t)peerSockets.size(), 1);
}


/**
 * @tc.name   : init socket client.
 * @tc.number : SoftbusTest_0101
 * @tc.desc   : test soft bus interface.
 */
HWTEST_F(SoftbusTest, SoftbusTest_0101, Function | SmallTest | Level1)
{
    DistributedServer::GetInstance().serverSocket_.clear();
    // add device
    DistributedDeviceInfo peerDevice;
    peerDevice.deviceId_ = "deviceId";
    peerDevice.networkId_ = "networkId";
    peerDevice.deviceType_ = DmDeviceType::DEVICE_TYPE_WATCH;
    DistributedClient::GetInstance().AddDevice(peerDevice);
    auto sockets = DistributedServer::GetInstance().serverSocket_;
    EXPECT_EQ((int32_t)sockets.size(), 0);

    // get socket id
    auto data = std::make_shared<NotifticationMatchBox>();
    data->SetLocalDeviceType(16);
    data->SetLocalDeviceId("local_device");
    data->Serialize();

    int32_t socketId = 0;
    int32_t result = DistributedClient::GetInstance().SendMessage(data,
        TransDataType::DATA_TYPE_MESSAGE, "deviceId", 0);
    EXPECT_EQ(result, 0);
    result = DistributedClient::GetInstance().SendMessage(data,
        TransDataType::DATA_TYPE_BYTES, "deviceId", 0);
    EXPECT_EQ(result, 0);

    auto remove = std::make_shared<NotificationRemoveBox>();
    remove->SetNotificationHashCode("hashcode");
    remove->Serialize();
    result = DistributedClient::GetInstance().SendMessage(remove,
        TransDataType::DATA_TYPE_BYTES, "deviceId", 0);
    EXPECT_EQ(result, 0);

    auto socketsId = DistributedClient::GetInstance().socketsId_;
    EXPECT_EQ((int32_t)socketsId.size(), 2);

    // release device
    DistributedClient::GetInstance().ReleaseDevice("deviceId", DmDeviceType::DEVICE_TYPE_WATCH);
}

/**
 * @tc.name   : test send adapter.
 * @tc.number : SoftbusTest_0102
 * @tc.desc   : test soft bus adapter.
 */
HWTEST_F(SoftbusTest, SoftbusTest_0102, Function | SmallTest | Level1)
{
    DistributedClient::GetInstance().socketsId_.clear();

    DistributedDeviceInfo peerDevice;
    peerDevice.deviceId_ = "deviceId";
    peerDevice.networkId_ = "networkId";
    peerDevice.deviceType_ = DmDeviceType::DEVICE_TYPE_WATCH;
    DistributedClient::GetInstance().AddDevice(peerDevice);

    // make data
    auto data = std::make_shared<NotifticationMatchBox>();
    data->SetLocalDeviceType(16);
    data->SetLocalDeviceId("local_device");
    data->Serialize();

    std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(data, peerDevice,
        TransDataType::DATA_TYPE_MESSAGE, MODIFY_ERROR_EVENT_CODE);
    DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
    sleep(2);
    auto socketsId = DistributedClient::GetInstance().socketsId_;
    EXPECT_EQ((int32_t)socketsId.size(), 1);
}

}  // namespace Notification
}  // namespace OHOS
