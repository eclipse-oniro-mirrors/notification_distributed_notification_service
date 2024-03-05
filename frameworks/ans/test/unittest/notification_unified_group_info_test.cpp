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
#include <memory>
#include <string>
#include "int_wrapper.h"
#include "notification_unified_group_Info.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationUnifiedGroupInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetUnifiedGroupInfo_00001
 * @tc.desc: Test set all info of UnifiedGroupInfo.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUnifiedGroupInfoTest, SetUnifiedGroupInfo_00001, Function | SmallTest | Level1)
{
    NotificationUnifiedGroupInfo info;
    info.SetKey("testKey");
    EXPECT_EQ(info.GetKey(), "testKey");

    info.SetTitle("testtitle");
    EXPECT_EQ(info.GetTitle(), "testtitle");

    info.SetContent("content");
    EXPECT_EQ(info.GetContent(), "content");

    info.SetSceneName("test");
    EXPECT_EQ(info.GetSceneName(), "test");

    std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<AAFwk::WantParams>();
    info.SetExtraInfo(extraInfo);
    EXPECT_NE(info.GetExtraInfo(), nullptr);
    std::string res = "NotificationUnifiedGroupInfo{ key = testKey, title = testtitle, "
        "content = content, sceneName = test, extraInfo = {} }";
    EXPECT_EQ(info.Dump(), res);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUnifiedGroupInfoTest, Marshalling_00001, Function | SmallTest | Level1)
{
    NotificationUnifiedGroupInfo info;
    info.SetKey("testKey");
    info.SetTitle("testtitle");
    info.SetContent("content");
    info.SetSceneName("test");

    Parcel parcel;
    EXPECT_EQ(info.Marshalling(parcel), true);
    auto ptr = NotificationUnifiedGroupInfo::Unmarshalling(parcel);
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(ptr->GetTitle(), "testtitle");
}

/**
 * @tc.name: Marshalling_00002
 * @tc.desc: Test Marshalling.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUnifiedGroupInfoTest, Marshalling_00002, Function | SmallTest | Level1)
{
    NotificationUnifiedGroupInfo info;
    info.SetKey("testKey");
    info.SetTitle("testtitle");
    info.SetContent("content");
    info.SetSceneName("test");
    std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IInterface> value = AAFwk::Integer::Box(1);
    extraInfo->SetParam(string("testId"), value);
    info.SetExtraInfo(extraInfo);

    Parcel parcel;
    EXPECT_EQ(info.Marshalling(parcel), true);
    auto ptr = NotificationUnifiedGroupInfo::Unmarshalling(parcel);
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(ptr->GetTitle(), "testtitle");
}
}
}
