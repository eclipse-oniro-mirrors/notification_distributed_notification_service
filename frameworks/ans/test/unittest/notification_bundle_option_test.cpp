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
#include "notification_bundle_option.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationBundleOptionTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetBundleName_00001
 * @tc.desc: Test SetBundleName parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationBundleOptionTest, SetBundleName_00001, Function | SmallTest | Level1)
{
    std::string bundleName = "BundleName";
    std::string bundleName1 = "BundleName1";
    int32_t uid = 10;
    auto rrc = std::make_shared<NotificationBundleOption>(bundleName, uid);
    rrc->SetBundleName(bundleName1);
    EXPECT_EQ(rrc->GetBundleName(), bundleName1);
}

/**
 * @tc.name: SetUid_00001
 * @tc.desc: Test SetUid parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationBundleOptionTest, SetUid_00001, Function | SmallTest | Level1)
{
    std::string bundleName = "BundleName";
    int32_t uid = 10;
    int32_t uid1 = 20;
    auto rrc = std::make_shared<NotificationBundleOption>(bundleName, uid);
    rrc->SetUid(uid1);
    EXPECT_EQ(rrc->GetUid(), uid1);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationBundleOptionTest, Dump_00001, Function | SmallTest | Level1)
{
    std::string bundleName = "BundleName";
    int32_t uid = 10;
    auto rrc = std::make_shared<NotificationBundleOption>(bundleName, uid);
    std::string ret =
        "NotificationBundleOption{ bundleName = BundleName, uid = 10, instanceKey = 0, appIndex = -1 }";
    EXPECT_EQ(rrc->Dump(), ret);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationBundleOptionTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    std::string bundleName = "BundleName";
    int32_t uid = 10;
    auto rrc = std::make_shared<NotificationBundleOption>(bundleName, uid);
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationBundleOptionTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::string bundleName = "BundleName";
    int32_t uid = 10;
    std::shared_ptr<NotificationBundleOption> result =
    std::make_shared<NotificationBundleOption>(bundleName, uid);

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
HWTEST_F(NotificationBundleOptionTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    std::string bundleName = "BundleName";
    int32_t uid = 10;
    auto rrc = std::make_shared<NotificationBundleOption>(bundleName, uid);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}

/**
 * @tc.name: JsonConvert_00001
 * @tc.desc: Test json convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationBundleOptionTest, JsonConvert_00001, Function | SmallTest | Level1)
{
    std::string bundleName = "BundleName";
    int32_t uid = 10;
    auto rrc = std::make_shared<NotificationBundleOption>(bundleName, uid);
    nlohmann::json jsonObject;
    EXPECT_TRUE(rrc->ToJson(jsonObject));
    auto *rrcNew = rrc->FromJson(jsonObject);
    EXPECT_EQ(rrcNew->GetBundleName(), rrc->GetBundleName());
    EXPECT_EQ(rrcNew->GetUid(), rrc->GetUid());
}
} // namespace Notification
} // namespace OHOS
