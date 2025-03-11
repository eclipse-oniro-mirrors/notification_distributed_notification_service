/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include <functional>
#include <gtest/gtest.h>

#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "swing_call_back_proxy.h"
#include "swing_call_back_stub.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class SwingCallBackTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
    void OnUpdateStatus(bool isEnable, int triggerMode) {};
};

/**
 * @tc.number    : SwingCallBackProxyTest_00100
 * @tc.name      : OnCheckNotification_0100
 * @tc.desc      : Test OnCheckNotification function
 */
HWTEST_F(SwingCallBackTest, SwingCallBackProxyTest_00100, Function | SmallTest | Level1)
{
    sptr<IRemoteObject> impl;
    SwingCallBackProxy swingCallBackProxy(impl);
    int32_t funcResult = -1;
    int ret = swingCallBackProxy.OnUpdateStatus(true, 0, funcResult);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
}

/**
 * @tc.number    : SwingCallBackStubTest_00100
 * @tc.name      : OnRemoteRequest_0100
 * @tc.desc      : Test OnRemoteRequest function
 */
HWTEST_F(SwingCallBackTest, SwingCallBackStubTest_00100, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(NotificationInterfaceCode::ON_UPDATE_STATUS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    SwingCallBackStub swingCallBackStub = SwingCallBackService(
        std::bind(&SwingCallBackTest::OnUpdateStatus, this, std::placeholders::_1, std::placeholders::_2));
    data.WriteInterfaceToken(swingCallBackStub.GetDescriptor());
    int ret = swingCallBackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.number    : SwingCallBackStubTest_00200
 * @tc.name      : OnRemoteRequest_0200
 * @tc.desc      : Test OnRemoteRequest function
 */
HWTEST_F(SwingCallBackTest, SwingCallBackStubTest_00200, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(NotificationInterfaceCode::ON_UPDATE_STATUS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    SwingCallBackStub swingCallBackStub;
    data.WriteInterfaceToken(swingCallBackStub.GetDescriptor());
    int ret = swingCallBackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_UNKNOWN_OBJECT);
}

/**
 * @tc.number    : SwingCallBackStubTest_00300
 * @tc.name      : OnRemoteRequest_0300
 * @tc.desc      : Test OnRemoteRequest function
 */
HWTEST_F(SwingCallBackTest, SwingCallBackStubTest_00300, Function | SmallTest | Level1)
{
    uint32_t code = 10;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    SwingCallBackStub swingCallBackStub;
    data.WriteInterfaceToken(swingCallBackStub.GetDescriptor());
    int ret = swingCallBackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_STATE);
}

/**
 * @tc.number    : SwingCallBackStubTest_00400
 * @tc.name      : OnRemoteRequest_0400
 * @tc.desc      : Test OnRemoteRequest function
 */
HWTEST_F(SwingCallBackTest, SwingCallBackStubTest_00400, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(NotificationInterfaceCode::ON_UPDATE_STATUS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    SwingCallBackStub swingCallBackStub;
    int ret = swingCallBackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_STATE);
}
}  // namespace Notification
}  // namespace OHOS
#endif