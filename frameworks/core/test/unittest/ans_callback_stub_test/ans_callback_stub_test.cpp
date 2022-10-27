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

#include "ans_callback_stub.h"
#include "ans_inner_errors.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

class AnsCallbackStubImpl : public AnsCallbackStub {
    bool OnEnableNotification(bool isAllow) override
    {
        return false;
    }
};

class AnsCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp()
    {
        ansCallbackStub_ = new AnsCallbackStubImpl();
    }
    void TearDown() {}
    sptr<AnsCallbackStub> ansCallbackStub_;
};

/**
 * @tc.name: OnRemoteRequest01
 * @tc.desc: Test if the descriptor is wrong.
 * @tc.type: FUNC
 * @tc.require: issueI5XO2O
 */
HWTEST_F(AnsCallbackStubTest, OnRemoteRequest01, Function | SmallTest | Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(u"error.GetDescriptor");

    int32_t ret = ansCallbackStub_->OnRemoteRequest(0, data, reply, option);
    EXPECT_EQ(ret, (int)OBJECT_NULL);
}

/**
 * @tc.name: OnRemoteRequest02
 * @tc.desc: Test if can not read a bool from data failed.
 * @tc.type: FUNC
 * @tc.require: issueI5XO2O
 */
HWTEST_F(AnsCallbackStubTest, OnRemoteRequest02, Function | SmallTest | Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsCallbackStub::GetDescriptor());

    int32_t ret = ansCallbackStub_->OnRemoteRequest(0, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: OnRemoteRequest03
 * @tc.desc: Test unknow code failed.
 * @tc.type: FUNC
 * @tc.require: issueI5XO2O
 */
HWTEST_F(AnsCallbackStubTest, OnRemoteRequest03, Function | SmallTest | Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsCallbackStub::GetDescriptor());

    int32_t ret = ansCallbackStub_->OnRemoteRequest(1, data, reply, option);
    EXPECT_EQ(ret, (int)IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: OnRemoteRequest04
 * @tc.desc: Test OnRemoteRequest success.
 * @tc.type: FUNC
 * @tc.require: issueI5XO2O
 */
HWTEST_F(AnsCallbackStubTest, OnRemoteRequest04, Function | SmallTest | Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsCallbackStub::GetDescriptor());
    data.WriteBool(true);

    int32_t ret = ansCallbackStub_->OnRemoteRequest(0, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}
