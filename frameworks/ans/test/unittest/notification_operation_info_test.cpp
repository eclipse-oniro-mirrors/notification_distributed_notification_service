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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "notification_operation_info.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationOperationInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetJumpType_0100
 * @tc.desc: Test SetJumpType.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationOperationInfoTest, SetJumpType_0100, Function | SmallTest | Level1)
{
    NotificationOperationInfo notificationOperationInfo;
    notificationOperationInfo.SetJumpType(1);
    EXPECT_EQ(notificationOperationInfo.GetJumpType(), 1);
}

/**
 * @tc.name: SetBtnIndex_0100
 * @tc.desc: Test SetBtnIndex.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationOperationInfoTest, SetBtnIndex_0100, Function | SmallTest | Level1)
{
    NotificationOperationInfo notificationOperationInfo;
    notificationOperationInfo.SetBtnIndex(2);
    EXPECT_EQ(notificationOperationInfo.GetBtnIndex(), 2);
}

/**
 * @tc.name: Dump_0100
 * @tc.desc: Test Dump.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationOperationInfoTest, Dump_0100, Function | SmallTest | Level1)
{
    NotificationOperationInfo notificationOperationInfo;
    std::string expString = "NotificationOperationInfo{ hashCode = hashCode, eventId = 1, actionName = actionName, " \
    "operationType = 0, btnIndex = 2, jumpType = 1 }";
    notificationOperationInfo.SetHashCode("hashCode");
    notificationOperationInfo.SetEventId("1");
    notificationOperationInfo.SetActionName("actionName");
    notificationOperationInfo.SetOperationType(OperationType::DISTRIBUTE_OPERATION_JUMP);
    notificationOperationInfo.SetJumpType(1);
    notificationOperationInfo.SetBtnIndex(2);
    EXPECT_EQ(notificationOperationInfo.Dump(), expString);
}

/**
 * @tc.name: Marshalling_0100
 * @tc.desc: Test Marshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationOperationInfoTest, Marshalling_0100, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationOperationInfo notificationOperationInfo;
    notificationOperationInfo.SetHashCode("hashCode");
    notificationOperationInfo.SetEventId("1");
    notificationOperationInfo.SetActionName("actionName");
    notificationOperationInfo.SetOperationType(OperationType::DISTRIBUTE_OPERATION_JUMP);
    notificationOperationInfo.SetBtnIndex(2);
    notificationOperationInfo.SetJumpType(1);
    notificationOperationInfo.SetNotificationUdid("udid");
    EXPECT_TRUE(notificationOperationInfo.Marshalling(parcel));
    NotificationOperationInfo ntfOperInfoRes;
    EXPECT_TRUE(ntfOperInfoRes.ReadFromParcel(parcel));
    EXPECT_EQ(ntfOperInfoRes.GetBtnIndex(), 2);
    EXPECT_EQ(ntfOperInfoRes.GetJumpType(), 1);
    EXPECT_EQ(ntfOperInfoRes.GetNotificationUdid(), "udid");
}
}
}