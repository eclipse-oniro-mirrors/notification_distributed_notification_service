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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "enabled_priority_notification_by_bundle_callback_data.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class EnabledPriorityNotificationByBundleCallbackDataTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetBundle_00001
 * @tc.desc: Test SetBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(EnabledPriorityNotificationByBundleCallbackDataTest, SetBundle_00001, Function | SmallTest | Level1)
{
    auto callback = std::make_shared<EnabledPriorityNotificationByBundleCallbackData>();
    callback->SetBundle("bundleName");
    EXPECT_EQ(callback->GetBundle(), "bundleName");
}

/**
 * @tc.name: SetUid_00001
 * @tc.desc: Test SetBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(EnabledPriorityNotificationByBundleCallbackDataTest, SetUid_00001, Function | SmallTest | Level1)
{
    auto callback = std::make_shared<EnabledPriorityNotificationByBundleCallbackData>();
    callback->SetUid(200202);
    EXPECT_EQ(callback->GetUid(), 200202);
}

/**
 * @tc.name: SetEnableStatus_00001
 * @tc.desc: Test SetBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(EnabledPriorityNotificationByBundleCallbackDataTest, SetEnableStatus_00001, Function | SmallTest | Level1)
{
    auto callback = std::make_shared<EnabledPriorityNotificationByBundleCallbackData>();
    callback->SetEnableStatus(NotificationConstant::PriorityEnableStatus::ENABLE);
    EXPECT_EQ(callback->GetEnableStatus(), NotificationConstant::PriorityEnableStatus::ENABLE);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test SetBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(EnabledPriorityNotificationByBundleCallbackDataTest, Marshalling_00001, Function | SmallTest | Level1)
{
    auto callback = std::make_shared<EnabledPriorityNotificationByBundleCallbackData>(
        "bundleName", 200202, NotificationConstant::PriorityEnableStatus::ENABLE);
    Parcel parcel;
    EXPECT_TRUE(callback->Marshalling(parcel));
    EnabledPriorityNotificationByBundleCallbackData *result = callback->Unmarshalling(parcel);
    EXPECT_EQ(result->Dump(),
        "EnabledPriorityNotificationByBundleCallbackData{ bundle = bundleName, uid = 200202, enableStatus = 2 }");
    delete result;
}
}
}