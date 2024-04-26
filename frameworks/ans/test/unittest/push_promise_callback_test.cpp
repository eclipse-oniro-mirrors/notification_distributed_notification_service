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

#include "push_promise_callback.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class PromiseCallbackInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Create_00001
 * @tc.desc: Test Create.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PromiseCallbackInfoTest, Create_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<PushCallBackParam> pushCallBackParam = std::make_shared<PushCallBackParam>();
    auto *callbackInfo = PromiseCallbackInfo::Create(pushCallBackParam);
    EXPECT_NE(callbackInfo, nullptr);
    auto pushCallBackParam_ = callbackInfo->GetJsCallBackParam();
    EXPECT_NE(pushCallBackParam.get(), nullptr);
    PromiseCallbackInfo::Destroy(callbackInfo);
}
}
}
