/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ans_log_wrapper.h"
#include "ans_dialog_host_client.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
class AnsDialogHostClientTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

class TestAnsDialogCallback final : public AnsDialogCallbackNativeInterface {
public:
    TestAnsDialogCallback() = default;
    ~TestAnsDialogCallback() override = default;

    void ProcessDialogStatusChanged(const DialogStatusData& data) override
    {
        ANS_LOGE("ProcessDialogStatusChanged err called.");
    }
};

/**
 * @tc.name: CreateIfNullptr_00001
 * @tc.desc: Test CreateIfNullptr.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsDialogHostClientTest, CreateIfNullptr_00001, Function | SmallTest | Level1)
{
    sptr<AnsDialogHostClient> client = nullptr;
    AnsDialogHostClient::CreateIfNullptr(client);
    client = AnsDialogHostClient::GetInstance();
    EXPECT_NE(client, nullptr);
}

/**
 * @tc.name: Destroy_00001
 * @tc.desc: Test Destroy.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsDialogHostClientTest, Destroy_00001, Function | SmallTest | Level1)
{
    sptr<AnsDialogHostClient> client = nullptr;
    AnsDialogHostClient::CreateIfNullptr(client);
    client = AnsDialogHostClient::GetInstance();
    EXPECT_NE(client, nullptr);
    client->Destroy();
    auto newClient = AnsDialogHostClient::GetInstance();
    EXPECT_EQ(newClient.GetRefPtr(), nullptr);
}
}
}
