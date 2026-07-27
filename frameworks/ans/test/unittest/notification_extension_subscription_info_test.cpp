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
#include "notification_extension_subscription_info.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationExtensionSubscriptionInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
* @tc.name: Constructor_00001
* @tc.desc: Test NotificationExtensionSubscriptionInfo parameters.
* @tc.type: FUNC
* @tc.require: issueI5WBBH
*/
HWTEST_F(NotificationExtensionSubscriptionInfoTest, Constructor_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SubscribeType type = NotificationConstant::SubscribeType::BLUETOOTH;
    std::string addr = "addrTest";
    auto subscriptionInfo = std::make_shared<NotificationExtensionSubscriptionInfo>(addr, type);
    ASSERT_NE(subscriptionInfo, nullptr);

    EXPECT_EQ(subscriptionInfo->GetAddr(), addr);
    EXPECT_EQ(subscriptionInfo->GetType(), type);
}

/**
* @tc.name: SetAddr_00001
* @tc.desc: Test SetAddr parameters.
* @tc.type: FUNC
* @tc.require: issueI5WBBH
*/
HWTEST_F(NotificationExtensionSubscriptionInfoTest, SetAddr_00001, Function | SmallTest | Level1)
{
    auto subscriptionInfo = std::make_shared<NotificationExtensionSubscriptionInfo>();
    ASSERT_NE(subscriptionInfo, nullptr);

    std::string addr = "addrTest";
    subscriptionInfo->SetAddr(addr);
    EXPECT_EQ(subscriptionInfo->GetAddr(), addr);
}

/**
* @tc.name: SetType_00001
* @tc.desc: Test SetType parameters.
* @tc.type: FUNC
* @tc.require: issueI5WBBH
*/
HWTEST_F(NotificationExtensionSubscriptionInfoTest, SetType_00001, Function | SmallTest | Level1)
{
    auto subscriptionInfo = std::make_shared<NotificationExtensionSubscriptionInfo>();
    ASSERT_NE(subscriptionInfo, nullptr);

    NotificationConstant::SubscribeType type = NotificationConstant::SubscribeType::BLUETOOTH;
    subscriptionInfo->SetType(type);
    EXPECT_EQ(subscriptionInfo->GetType(), type);
}

/**
* @tc.name: SetHfp_00001
* @tc.desc: Test SetHfp parameters.
* @tc.type: FUNC
* @tc.require: issueI5WBBH
*/
HWTEST_F(NotificationExtensionSubscriptionInfoTest, SetHfp_00001, Function | SmallTest | Level1)
{
    auto subscriptionInfo = std::make_shared<NotificationExtensionSubscriptionInfo>();
    ASSERT_NE(subscriptionInfo, nullptr);

    EXPECT_FALSE(subscriptionInfo->IsHfp());
    subscriptionInfo->SetHfp(true);
    EXPECT_TRUE(subscriptionInfo->IsHfp());
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationExtensionSubscriptionInfoTest, Dump_00001, Function | SmallTest | Level1)
{
    auto subscriptionInfo = std::make_shared<NotificationExtensionSubscriptionInfo>();
    std::string ret = "NotificationExtensionSubscriptionInfo{ addr = , type = 0 }";
    ASSERT_NE(subscriptionInfo, nullptr);

    EXPECT_EQ(subscriptionInfo->Dump(), ret);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationExtensionSubscriptionInfoTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto subscriptionInfo = std::make_shared<NotificationExtensionSubscriptionInfo>();
    ASSERT_NE(subscriptionInfo, nullptr);

    EXPECT_TRUE(subscriptionInfo->Marshalling(parcel));
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationExtensionSubscriptionInfoTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteString("addr1");
    parcel.WriteInt32(0);

    auto subscriptionInfo = std::make_shared<NotificationExtensionSubscriptionInfo>();
    ASSERT_NE(subscriptionInfo, nullptr);
    auto ret = subscriptionInfo->Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters with json nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationExtensionSubscriptionInfoTest, FromJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;

    sptr<NotificationExtensionSubscriptionInfo> ret = NotificationExtensionSubscriptionInfo::FromJson(jsonObject);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters with json not object.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationExtensionSubscriptionInfoTest, FromJson_00002, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{"addr", "isHfp", "type"};

    EXPECT_FALSE(jsonObject.is_object());
    sptr<NotificationExtensionSubscriptionInfo> ret = NotificationExtensionSubscriptionInfo::FromJson(jsonObject);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: FromJson_00003
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationExtensionSubscriptionInfoTest, FromJson_00003, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{{"addr", "addr1"}, {"isHfp", true}, {"type", 0}};

    EXPECT_TRUE(jsonObject.is_object());
    sptr<NotificationExtensionSubscriptionInfo> ret = NotificationExtensionSubscriptionInfo::FromJson(jsonObject);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationExtensionSubscriptionInfoTest, ToJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{{"addr", "addr1"}, {"isHfp", true}, {"type", 0}};
    sptr<NotificationExtensionSubscriptionInfo> subscriptionInfo =
        NotificationExtensionSubscriptionInfo::FromJson(jsonObject);
    ASSERT_NE(subscriptionInfo, nullptr);

    sptr<NotificationExtensionSubscriptionInfo> ret = NotificationExtensionSubscriptionInfo::FromJson(jsonObject);
    EXPECT_NE(ret, nullptr);
    EXPECT_TRUE(subscriptionInfo->ToJson(jsonObject));
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationExtensionSubscriptionInfoTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteString("addr1");
    parcel.WriteInt32(0);

    auto subscriptionInfo = std::make_shared<NotificationExtensionSubscriptionInfo>();
    ASSERT_NE(subscriptionInfo, nullptr);

    EXPECT_TRUE(subscriptionInfo->ReadFromParcel(parcel));
}
}
}