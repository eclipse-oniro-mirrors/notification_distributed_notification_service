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
#include "notification_template.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationTemplateTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetTemplateName_00001
 * @tc.desc: Test SetTemplateName parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTemplateTest, SetTemplateName_00001, Function | SmallTest | Level1)
{
    std::string name = "Name";
    auto rrc = std::make_shared<NotificationTemplate>();
    rrc->SetTemplateName(name);
    EXPECT_EQ(rrc->GetTemplateName(), name);
}

/**
 * @tc.name: SetTemplateData_00001
 * @tc.desc: Test SetTemplateData parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTemplateTest, SetTemplateData_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<AAFwk::WantParams> data = std::make_shared<AAFwk::WantParams>();
    auto rrc = std::make_shared<NotificationTemplate>();
    rrc->SetTemplateData(data);
    EXPECT_EQ(rrc->GetTemplateData(), data);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTemplateTest, Dump_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationTemplate>();
    std::string ret = "templateName = , templateData = null";
    EXPECT_EQ(rrc->Dump(), ret);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationTemplateTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationTemplate>();
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTemplateTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationTemplate> result =
    std::make_shared<NotificationTemplate>();

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, false);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTemplateTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationTemplate>();
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}
}
}