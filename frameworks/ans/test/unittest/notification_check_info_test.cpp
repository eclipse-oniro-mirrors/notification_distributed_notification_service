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

#include "notification_check_info.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationCheckInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetPkgName_00001
 * @tc.desc: Test SetPkgName.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckInfoTest, SetPkgName_00001, Function | SmallTest | Level1)
{
    NotificationCheckInfo checkInfo;
    checkInfo.SetPkgName("test");
    EXPECT_EQ("test", checkInfo.GetPkgName());
}

/**
 * @tc.name: SetNotifyId_00001
 * @tc.desc: Test GetNotifyId.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckInfoTest, GetNotifyId_00001, Function | SmallTest | Level1)
{
    NotificationCheckInfo checkInfo;
    checkInfo.SetNotifyId(1);
    EXPECT_EQ(1, checkInfo.GetNotifyId());
}

/**
 * @tc.name: SetContentType_00001
 * @tc.desc: Test SetContentType.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckInfoTest, SetContentType_00001, Function | SmallTest | Level1)
{
    NotificationCheckInfo checkInfo;
    checkInfo.SetContentType(1);
    EXPECT_EQ(1, checkInfo.GetContentType());
}

/**
 * @tc.name: SetCreatorUserId_00001
 * @tc.desc: Test SetCreatorUserId.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckInfoTest, SetCreatorUserId_00001, Function | SmallTest | Level1)
{
    NotificationCheckInfo checkInfo;
    checkInfo.SetCreatorUserId(1);
    EXPECT_EQ(1, checkInfo.GetCreatorUserId());
}

/**
 * @tc.name: SetSlotType_00001
 * @tc.desc: Test SetSlotType.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckInfoTest, SetSlotType_00001, Function | SmallTest | Level1)
{
    NotificationCheckInfo checkInfo;
    checkInfo.SetSlotType(1);
    EXPECT_EQ(1, checkInfo.GetSlotType());
}

/**
 * @tc.name: SetLabel_00001
 * @tc.desc: Test SetLabel.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckInfoTest, SetLabel_00001, Function | SmallTest | Level1)
{
    NotificationCheckInfo checkInfo;
    checkInfo.SetLabel("testTag");
    EXPECT_EQ("testTag", checkInfo.GetLabel());
}

/**
 * @tc.name: SetExtraInfo_00001
 * @tc.desc: Test SetExtraInfo.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckInfoTest, SetExtraInfo_00001, Function | SmallTest | Level1)
{
    NotificationCheckInfo checkInfo;
    std::shared_ptr<AAFwk::WantParams> wantParams = std::make_shared<AAFwk::WantParams>();
    checkInfo.SetExtraInfo(wantParams);
    EXPECT_NE(nullptr, checkInfo.GetExtraInfo());
}

/**
 * @tc.name: ConvertJsonStringToValue_00001
 * @tc.desc: Test ConvertJsonStringToValue.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckInfoTest, ConvertJsonStringToValue_00001, Function | SmallTest | Level1)
{
    NotificationCheckInfo checkInfo;
    std::string obj = "{\"pkgName\":\"test\", \"notifyId\":1, \"contentType\":1,"
        "\"creatorUserId\":1, \"slotType\":1, \"label\":\"testTag\", \"extraInfo\":\"{}\"}";
    checkInfo.ConvertJsonStringToValue(obj);

    EXPECT_EQ("testTag", checkInfo.GetLabel());
}

/**
 * @tc.name: ConvertJsonStringToValue_00002
 * @tc.desc: Test ConvertJsonStringToValue and json is null.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckInfoTest, ConvertJsonStringToValue_00002, Function | SmallTest | Level1)
{
    NotificationCheckInfo checkInfo;
    std::string obj = "{}";
    checkInfo.ConvertJsonStringToValue(obj);

    EXPECT_EQ("", checkInfo.GetLabel());
}
}
}
