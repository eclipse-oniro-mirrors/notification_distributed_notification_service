/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <functional>
#include <gtest/gtest.h>

#include "ans_inner_errors.h"
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "push_callback_proxy.h"
#include "push_callback_stub.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class PushCallBackStubTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

class TestPushCallBackStub : public PushCallBackStub {
public:
    TestPushCallBackStub() = default;
    virtual ~TestPushCallBackStub()
    {};
    int32_t OnCheckNotification(
        const std::string &notificationData, const std::shared_ptr<PushCallBackParam> &pushCallBackParam) override
    {
        return 0;
    }
};

/**
 * @tc.number    : PushCallBackStubTest_00100
 * @tc.name      : OnRemoteRequest_0100
 * @tc.desc      : Test OnRemoteRequest function
 */
HWTEST_F(PushCallBackStubTest, PushCallBackStubTest_00100, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(NotificationInterfaceCode::ON_CHECK_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    data.WriteInterfaceToken(u"error.GetDescriptor");

    TestPushCallBackStub testPushCallBackStub;
    int ret = testPushCallBackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_STATE);
}

/**
 * @tc.number    : PushCallBackStubTest_00300
 * @tc.name      : OnRemoteRequest_0300
 * @tc.desc      : Test OnRemoteRequest function
 */
HWTEST_F(PushCallBackStubTest, PushCallBackStubTest_00300, Function | SmallTest | Level1)
{
    uint32_t code = 10;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    TestPushCallBackStub testPushCallBackStub;
    data.WriteInterfaceToken(testPushCallBackStub.GetDescriptor());

    int ret = testPushCallBackStub.OnRemoteRequest(code, data, reply, option);
    int errcode = 305;
    EXPECT_EQ(ret, errcode);
}

/**
 * @tc.number    : PushCallBackStubTest_00400
 * @tc.name      : OnCheckNotification_0100
 * @tc.desc      : Test OnCheckNotification function
 */
HWTEST_F(PushCallBackStubTest, PushCallBackStubTest_00400, Function | SmallTest | Level1)
{
    sptr<IRemoteObject> impl;
    PushCallBackProxy pushCallBackProxy(impl);

    int ret = pushCallBackProxy.OnCheckNotification("", nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : PushCallBackStubTest_00600
 * @tc.name      : OnCheckNotification_0200
 * @tc.desc      : Test OnCheckNotification function
 */
HWTEST_F(PushCallBackStubTest, PushCallBackStubTest_00600, Function | SmallTest | Level1)
{
    sptr<IRemoteObject> impl;
    PushCallBackProxy pushCallBackProxy(impl);

    std::string notificationData = "this is notificationData";
    int ret = pushCallBackProxy.OnCheckNotification(notificationData, nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : ConvertPushCheckCodeToErrCode_00100
 * @tc.name      : ConvertPushCheckCodeToErrCode_00100
 * @tc.desc      : Test ConvertPushCheckCodeToErrCode function
 */
HWTEST_F(PushCallBackStubTest, ConvertPushCheckCodeToErrCode_00100, Function | SmallTest | Level1)
{
    int pushCheckCode = 0;
    TestPushCallBackStub testPushCallBackStub;
    ErrCode ret = testPushCallBackStub.ConvertPushCheckCodeToErrCode(pushCheckCode);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.number    : ConvertPushCheckCodeToErrCode_00200
 * @tc.name      : ConvertPushCheckCodeToErrCode_00200
 * @tc.desc      : Test ConvertPushCheckCodeToErrCode function
 */
HWTEST_F(PushCallBackStubTest, ConvertPushCheckCodeToErrCode_00200, Function | SmallTest | Level1)
{
    int pushCheckCode = 1;
    TestPushCallBackStub testPushCallBackStub;
    ErrCode ret = testPushCallBackStub.ConvertPushCheckCodeToErrCode(pushCheckCode);
    EXPECT_EQ(ret, (int)ERR_ANS_TASK_ERR);
}

/**
 * @tc.number    : ConvertPushCheckCodeToErrCode_00300
 * @tc.name      : ConvertPushCheckCodeToErrCode_00300
 * @tc.desc      : Test ConvertPushCheckCodeToErrCode function
 */
HWTEST_F(PushCallBackStubTest, ConvertPushCheckCodeToErrCode_00300, Function | SmallTest | Level1)
{
    int pushCheckCode = 2;
    TestPushCallBackStub testPushCallBackStub;
    ErrCode ret = testPushCallBackStub.ConvertPushCheckCodeToErrCode(pushCheckCode);
    EXPECT_EQ(ret, (int)ERR_ANS_PUSH_CHECK_NETWORK_UNREACHABLE);
}

/**
 * @tc.number    : ConvertPushCheckCodeToErrCode_00400
 * @tc.name      : ConvertPushCheckCodeToErrCode_00400
 * @tc.desc      : Test ConvertPushCheckCodeToErrCode function
 */
HWTEST_F(PushCallBackStubTest, ConvertPushCheckCodeToErrCode_00400, Function | SmallTest | Level1)
{
    int pushCheckCode = 3;
    TestPushCallBackStub testPushCallBackStub;
    ErrCode ret = testPushCallBackStub.ConvertPushCheckCodeToErrCode(pushCheckCode);
    EXPECT_EQ(ret, (int)ERR_ANS_PUSH_CHECK_FAILED);
}

/**
 * @tc.number    : ConvertPushCheckCodeToErrCode_00500
 * @tc.name      : ConvertPushCheckCodeToErrCode_00500
 * @tc.desc      : Test ConvertPushCheckCodeToErrCode function
 */
HWTEST_F(PushCallBackStubTest, ConvertPushCheckCodeToErrCode_00500, Function | SmallTest | Level1)
{
    int pushCheckCode = 4;
    TestPushCallBackStub testPushCallBackStub;
    ErrCode ret = testPushCallBackStub.ConvertPushCheckCodeToErrCode(pushCheckCode);
    EXPECT_EQ(ret, (int)ERR_ANS_TASK_ERR);
}

/**
 * @tc.number    : ConvertPushCheckCodeToErrCode_00600
 * @tc.name      : ConvertPushCheckCodeToErrCode_00600
 * @tc.desc      : Test ConvertPushCheckCodeToErrCode function
 */
HWTEST_F(PushCallBackStubTest, ConvertPushCheckCodeToErrCode_00600, Function | SmallTest | Level1)
{
    int pushCheckCode = 5;
    TestPushCallBackStub testPushCallBackStub;
    ErrCode ret = testPushCallBackStub.ConvertPushCheckCodeToErrCode(pushCheckCode);
    EXPECT_EQ(ret, (int)ERR_ANS_PUSH_CHECK_EXTRAINFO_INVALID);
}

/**
 * @tc.number    : ConvertPushCheckCodeToErrCode_00700
 * @tc.name      : ConvertPushCheckCodeToErrCode_00700
 * @tc.desc      : Test ConvertPushCheckCodeToErrCode function
 */
HWTEST_F(PushCallBackStubTest, ConvertPushCheckCodeToErrCode_00700, Function | SmallTest | Level1)
{
    int pushCheckCode = -1;
    TestPushCallBackStub testPushCallBackStub;
    ErrCode ret = testPushCallBackStub.ConvertPushCheckCodeToErrCode(pushCheckCode);
    EXPECT_EQ(ret, (int)ERR_ANS_PUSH_CHECK_FAILED);
}
}  // namespace Notification
}  // namespace OHOS
