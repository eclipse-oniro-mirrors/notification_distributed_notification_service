/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "notification_basic_content.h"
#include "notification_content.h"
#undef private 
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationContentTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: NotificationContentMarshalling_0100
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationContentMarshalling_0100, Level1)
{
    Parcel parcel;
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    NotificationContent notificationContent(normalContent);
    auto result = notificationContent.Marshalling(parcel);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: NotificationContentReadFromParcel_0100
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationContentReadFromParcel_0100, Level1)
{
    Parcel parcel;
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    NotificationContent notificationContent(normalContent);
    auto result = notificationContent.ReadFromParcel(parcel);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: NotificationBasicContentGetAdditionalText_0100
 * @tc.desc: GetAdditionalText
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationBasicContentGetAdditionalText_0100, Level1)
{
    std::string additionalText = "test";
    NotificationBasicContent notificationBasicContent;
    notificationBasicContent.SetAdditionalText(additionalText);
    auto result = notificationBasicContent.GetAdditionalText();
    EXPECT_EQ(result, additionalText);
}

/**
 * @tc.name: NotificationBasicContentGetText_0100
 * @tc.desc: GetText
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationBasicContentGetText_0100, Level1)
{
    std::string Text = "test";
    NotificationBasicContent notificationBasicContent;
    notificationBasicContent.SetText(Text);
    auto result = notificationBasicContent.GetText();
    EXPECT_EQ(result, Text);
}

/**
 * @tc.name: NotificationBasicContentGetTitle_0100
 * @tc.desc: GetTitle
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationBasicContentGetTitle_0100, Level1)
{
    std::string title = "titleTest";
    NotificationBasicContent notificationBasicContent;
    notificationBasicContent.SetTitle(title);
    auto result = notificationBasicContent.GetTitle();
    EXPECT_EQ(result, title);
}

/**
 * @tc.name: NotificationBasicContentMarshalling_0100
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationBasicContentMarshalling_0100, Level1)
{
    Parcel parcel;
    NotificationBasicContent notificationBasicContent;
    auto result = notificationBasicContent.Marshalling(parcel);
    EXPECT_EQ(result, true);
}
}
}
