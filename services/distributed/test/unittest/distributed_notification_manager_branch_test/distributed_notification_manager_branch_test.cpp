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

#include "gtest/gtest.h"
#define private public
#include "ans_inner_errors.h"
#include "distributed_notification_manager.h"

using namespace testing::ext;
extern void MockOnDeviceConnected(bool mockRet);
extern void MockGetEntriesFromDistributedDB(bool mockRet);
extern void MockGetDeviceInfoList(bool mockRet);
extern void MockGetLocalDeviceId(bool mockRet);

namespace OHOS {
namespace Notification {
class DistributedNotificationManagerBranchTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

public:
    virtual void OnPublish(
        const std::string &deviceId, const std::string &bundleName, sptr<NotificationRequest> &request) {};
    virtual void OnUpdate(
        const std::string &deviceId, const std::string &bundleName, sptr<NotificationRequest> &request) {};
    virtual void OnDelete(
        const std::string &deviceId, const std::string &bundleName, const std::string &label, int32_t id) {};

protected:
    std::shared_ptr<DistributedNotificationManager> distributedManager_;
};

void DistributedNotificationManagerBranchTest::SetUp()
{
    distributedManager_ = DistributedNotificationManager::GetInstance();
}

void DistributedNotificationManagerBranchTest::TearDown()
{
    distributedManager_ = nullptr;
    DistributedNotificationManager::DestroyInstance();
}

/**
 * @tc.name      : DistributedNotificationManager_00100
 * @tc.number    : DistributedNotificationManager_00100
 * @tc.desc      : test OnDeviceConnected function and database_ == nullptr.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_0100, Function | SmallTest | Level1)
{
    ASSERT_NE(nullptr, distributedManager_);
    distributedManager_->database_ = nullptr;
    distributedManager_->OnDeviceConnected("test");
}

/**
 * @tc.name      : DistributedNotificationManager_00200
 * @tc.number    : DistributedNotificationManager_00200
 * @tc.desc      : test OnDeviceConnected function and database_->OnDeviceConnected is false.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_00200, Function | SmallTest | Level1)
{
    ASSERT_NE(nullptr, distributedManager_);
    MockOnDeviceConnected(false);
    distributedManager_->OnDeviceConnected("test");
}

/**
 * @tc.name      : DistributedNotificationManager_00300
 * @tc.number    : DistributedNotificationManager_00300
 * @tc.desc      : test OnDeviceDisconnected function and GetEntriesFromDistributedDB is false.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_00300, Function | SmallTest | Level1)
{
    ASSERT_NE(nullptr, distributedManager_);
    MockGetEntriesFromDistributedDB(false);
    distributedManager_->OnDeviceDisconnected("test");
}

/**
 * @tc.name      : DistributedNotificationManager_00400
 * @tc.number    : DistributedNotificationManager_00400
 * @tc.desc      : test OnDeviceDisconnected function and ResolveDistributedKey is false.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_00400, Function | SmallTest | Level1)
{
    ASSERT_NE(nullptr, distributedManager_);
    MockGetEntriesFromDistributedDB(true);
    distributedManager_->OnDeviceDisconnected("test");
}

/**
 * @tc.name      : DistributedNotificationManager_00700
 * @tc.number    : DistributedNotificationManager_00700
 * @tc.desc      : test PublishCallback function and callback_.OnPublish is not nullptr.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_00700, Function | SmallTest | Level1)
{
    DistributedNotificationManager::IDistributedCallback callback = {
        .OnPublish = std::bind(&DistributedNotificationManagerBranchTest::OnPublish,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnUpdate = std::bind(&DistributedNotificationManagerBranchTest::OnUpdate,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnDelete = std::bind(&DistributedNotificationManagerBranchTest::OnDelete,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3,
            std::placeholders::_4),
    };
    distributedManager_->callback_ = callback;
    std::string deviceId = "test1";
    std::string bundleName = "test2";
    sptr<NotificationRequest> request = nullptr;
    EXPECT_EQ(distributedManager_->PublishCallback(deviceId, bundleName, request), true);
}

/**
 * @tc.name      : DistributedNotificationManager_00800
 * @tc.number    : DistributedNotificationManager_00800
 * @tc.desc      : test UpdateCallback function and callback_.OnUpdate is not nullptr.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_00800, Function | SmallTest | Level1)
{
    DistributedNotificationManager::IDistributedCallback callback = {
        .OnPublish = std::bind(&DistributedNotificationManagerBranchTest::OnPublish,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnUpdate = std::bind(&DistributedNotificationManagerBranchTest::OnUpdate,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnDelete = std::bind(&DistributedNotificationManagerBranchTest::OnDelete,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3,
            std::placeholders::_4),
    };
    distributedManager_->callback_ = callback;
    std::string deviceId = "test1";
    std::string bundleName = "test2";
    sptr<NotificationRequest> request = nullptr;
    EXPECT_EQ(distributedManager_->UpdateCallback(deviceId, bundleName, request), true);
}

/**
 * @tc.name      : DistributedNotificationManager_00900
 * @tc.number    : DistributedNotificationManager_00900
 * @tc.desc      : test DeleteCallback function and callback_.OnDelete is not nullptr.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_00900, Function | SmallTest | Level1)
{
    DistributedNotificationManager::IDistributedCallback callback = {
        .OnPublish = std::bind(&DistributedNotificationManagerBranchTest::OnPublish,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnUpdate = std::bind(&DistributedNotificationManagerBranchTest::OnUpdate,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnDelete = std::bind(&DistributedNotificationManagerBranchTest::OnDelete,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3,
            std::placeholders::_4),
    };
    distributedManager_->callback_ = callback;
    std::string deviceId = "test1";
    std::string bundleName = "test2";
    std::string label = "test3";
    int32_t id = 1;
    EXPECT_EQ(distributedManager_->DeleteCallback(deviceId, bundleName, label, id), true);
}

/**
 * @tc.name      : DistributedNotificationManager_01000
 * @tc.number    : DistributedNotificationManager_01000
 * @tc.desc      : test Publish function and ConvertToJsonString is false.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_01000, Function | SmallTest | Level1)
{
    MockGetLocalDeviceId(true);
    std::string bundleName = "aa";
    std::string label = "bb";
    int32_t id = 1;
    sptr<NotificationRequest> request = nullptr;
    EXPECT_EQ(distributedManager_->Publish(bundleName, label, id, request), ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name      : DistributedNotificationManager_01100
 * @tc.number    : DistributedNotificationManager_01100
 * @tc.desc      : test Update function and ConvertToJsonString is false.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_01100, Function | SmallTest | Level1)
{
    MockGetLocalDeviceId(true);
    std::string bundleName = "aa";
    std::string label = "bb";
    int32_t id = 1;
    sptr<NotificationRequest> request = nullptr;
    EXPECT_EQ(distributedManager_->Update(bundleName, label, id, request), ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name      : DistributedNotificationManager_01200
 * @tc.number    : DistributedNotificationManager_01200
 * @tc.desc      : test Update function and PutToDistributedDB is false.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_01200, Function | SmallTest | Level1)
{
    MockGetLocalDeviceId(true);
    sptr<NotificationRequest> request = new NotificationRequest(1000);
    request->SetLabel("<label>");

    std::string bundleName = "<bundleName>";
    std::string label = request->GetLabel();
    int32_t id = request->GetNotificationId();

    EXPECT_EQ(distributedManager_->Update(bundleName, label, id, request), ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name      : DistributedNotificationManager_01300
 * @tc.number    : DistributedNotificationManager_01300
 * @tc.desc      : test Delete function and GenerateLocalDistributedKey is false.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_01300, Function | SmallTest | Level1)
{
    MockGetLocalDeviceId(false);
    std::string bundleName = "aa";
    std::string label = "bb";
    int32_t id = 1;
    EXPECT_EQ(distributedManager_->Delete(bundleName, label, id), ERR_ANS_DISTRIBUTED_GET_INFO_FAILED);
}

/**
 * @tc.name      : DistributedNotificationManager_01400
 * @tc.number    : DistributedNotificationManager_01400
 * @tc.desc      : test DeleteRemoteNotification and DeleteToDistributedDB is false.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_01400, Function | SmallTest | Level1)
{
    std::string deviceId = "<deviceid>";
    std::string bundleName = "aa";
    std::string label = "bb";
    int32_t id = 1;
    EXPECT_EQ(distributedManager_->DeleteRemoteNotification(deviceId, bundleName, label, id),
        ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name      : DistributedNotificationManager_01500
 * @tc.number    : DistributedNotificationManager_01500
 * @tc.desc      : test GetCurrentDistributedNotification and GetEntriesFromDistributedDB is false.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_01500, Function | SmallTest | Level1)
{
    MockGetEntriesFromDistributedDB(false);
    std::vector<sptr<NotificationRequest>> requestList;
    EXPECT_EQ(
        distributedManager_->GetCurrentDistributedNotification(requestList), ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name      : DistributedNotificationManager_01600
 * @tc.number    : DistributedNotificationManager_01600
 * @tc.desc      : test GetCurrentDistributedNotification and ResolveDistributedKey is false.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_01600, Function | SmallTest | Level1)
{
    MockGetEntriesFromDistributedDB(true);
    std::vector<sptr<NotificationRequest>> requestList;
    EXPECT_EQ(
        distributedManager_->GetCurrentDistributedNotification(requestList), ERR_OK);
}

/**
 * @tc.name      : DistributedNotificationManager_01700
 * @tc.number    : DistributedNotificationManager_01700
 * @tc.desc      : test GetLocalDeviceInfo and GetLocalDeviceInfo is false.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_01700, Function | SmallTest | Level1)
{
    DistributedDatabase::DeviceInfo deviceInfo;
    EXPECT_EQ(
        distributedManager_->GetLocalDeviceInfo(deviceInfo), ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name      : DistributedNotificationManager_01800
 * @tc.number    : DistributedNotificationManager_01800
 * @tc.desc      : test OnDistributedKvStoreDeathRecipient and RecreateDistributedDB is false.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_01800, Function | SmallTest | Level1)
{
    EXPECT_EQ(
        distributedManager_->OnDistributedKvStoreDeathRecipient(), ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name      : DistributedNotificationManager_01900
 * @tc.number    : DistributedNotificationManager_01900
 * @tc.desc      : test OnDistributedKvStoreDeathRecipient and database_ is nullptr.
 */
HWTEST_F(DistributedNotificationManagerBranchTest, DistributedNotificationManager_01900, Function | SmallTest | Level1)
{
    distributedManager_->database_ = nullptr;
    EXPECT_EQ(
        distributedManager_->OnDistributedKvStoreDeathRecipient(), ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}
}  // namespace Notification
}  // namespace OHOS