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

#include "gtest/gtest.h"
#include "advanced_aggregation_data_roaming_observer.h"
#define private public
#include "advanced_datashare_helper.h"
#undef private
#include "mock_datashare.h"

using namespace testing::ext;

extern void MockGetSystemAbilityManager(bool mockRet);

namespace OHOS {
namespace Notification {

// Test suite
class AdvancedDatashareHelperTest : public ::testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

// Test cases
HWTEST_F(AdvancedDatashareHelperTest, Query_0001, Function | SmallTest | Level1)
{
    MockGetSystemAbilityManager(false);
    AdvancedDatashareHelper::SetIsDataShareReady(true);
    AdvancedDatashareHelper advancedDatashareHelper;
    int32_t userId = 100;
    Uri enableUri(advancedDatashareHelper.GetFocusModeEnableUri(userId));
    std::string enable;
    size_t dataShareItemSize = advancedDatashareHelper.dataShareItems_.size();
    bool ret = advancedDatashareHelper.Query(enableUri, KEY_FOCUS_MODE_ENABLE, enable);
    EXPECT_TRUE(ret);
    EXPECT_EQ(advancedDatashareHelper.dataShareItems_.size(), dataShareItemSize + 1);
}

HWTEST_F(AdvancedDatashareHelperTest, Query_0002, Function | SmallTest | Level1)
{
    AdvancedDatashareHelper::SetIsDataShareReady(false);
    MockGetSystemAbilityManager(false);
    AdvancedDatashareHelper advancedDatashareHelper;
    int32_t userId = 100;
    Uri enableUri(advancedDatashareHelper.GetFocusModeEnableUri(userId));
    std::string enable;
    bool ret = advancedDatashareHelper.Query(enableUri, KEY_FOCUS_MODE_ENABLE, enable);
    EXPECT_EQ(ret, false);

    AdvancedDatashareHelper::SetIsDataShareReady(true);
    MockIsFailedToQueryDataShareResultSet(true);
    ret = advancedDatashareHelper.Query(enableUri, KEY_FOCUS_MODE_ENABLE, enable);
    EXPECT_EQ(ret, false);

    MockIsFailedGoToFirstRow(1);
    MockIsFailedToQueryDataShareResultSet(false);
    ret = advancedDatashareHelper.Query(enableUri, KEY_FOCUS_MODE_ENABLE, enable);
    EXPECT_EQ(ret, false);
}

HWTEST_F(AdvancedDatashareHelperTest, Init_0001, Function | SmallTest | Level1)
{
    MockGetSystemAbilityManager(false);
    AdvancedDatashareHelper::SetIsDataShareReady(true);
    AdvancedDatashareHelper advancedDatashareHelper;
    advancedDatashareHelper.Init();
    EXPECT_EQ(advancedDatashareHelper.dataObservers_.size(), 5);
}

// Test cases
HWTEST_F(AdvancedDatashareHelperTest, QueryContact_0001, Function | SmallTest | Level1)
{
    MockGetSystemAbilityManager(false);
    MockSetRowCount(0);
    MockIsFailedToCreateDataShareHelper(true);
    MockIsFailedGoToFirstRow(0);

    AdvancedDatashareHelper advancedDatashareHelper;
    std::string uri = "datashare:///com.ohos.contactsdataability/contacts/contact_data?Proxy=true";
    Uri contactUri(uri);
    std::string phoneNumber = "11111111111";

    bool ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "6", "1", "true");
    EXPECT_EQ(ret, 1);

    MockIsFailedToCreateDataShareHelper(false);
    AdvancedDatashareHelper::SetIsDataShareReady(true);
    ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "6", "1", "true");
    EXPECT_EQ(ret, 1);
}

HWTEST_F(AdvancedDatashareHelperTest, QueryContact_0002, Function | SmallTest | Level1)
{
    std::string str = "0";
    MockGetStringValue(str);
    MockGetSystemAbilityManager(false);
    MockIsFailedToQueryDataShareResultSet(false);
    MockIsFailedToCreateDataShareHelper(false);
    MockSetRowCount(1);
    MockGoToGetNextRow(-1);
    MockIsFailedGoToFirstRow(0);

    AdvancedDatashareHelper advancedDatashareHelper;
    std::string uri = advancedDatashareHelper.GetFocusModeRepeatCallUri(0);
    Uri contactUri(uri);
    std::string phoneNumber = "1111";
    AdvancedDatashareHelper::SetIsDataShareReady(true);

    bool ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "5", "1", "true");
    EXPECT_EQ(ret, 0);

    str = "1";
    MockGetStringValue(str);
    ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "5", "1", "true");
    EXPECT_EQ(ret, 1);

    str = "2";
    MockGetStringValue(str);
    ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "5", "1", "true");
    EXPECT_EQ(ret, 0);

    ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "10", "1", "true");
    EXPECT_EQ(ret, 1);
}

HWTEST_F(AdvancedDatashareHelperTest, QueryContact_0003, Function | SmallTest | Level1)
{
    MockGetSystemAbilityManager(false);
    MockIsFailedToCreateDataShareHelper(true);
    MockIsFailedToQueryDataShareResultSet(true);
    MockIsFailedGoToFirstRow(0);
    AdvancedDatashareHelper advancedDatashareHelper;
    std::string uri = advancedDatashareHelper.GetIntelligentExperienceUri(0);
    Uri contactUri(uri);
    std::string phoneNumber = "11111111111";

    int ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "10", "1", "true");
    EXPECT_EQ(ret, -1);

    MockIsFailedToCreateDataShareHelper(false);
    ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "10", "1", "true");
    EXPECT_EQ(ret, -1);
}

// Test cases
HWTEST_F(AdvancedDatashareHelperTest, QueryContact_0004, Function | SmallTest | Level1)
{
    MockGetSystemAbilityManager(false);
    MockSetRowCount(1);
    MockIsFailedToCreateDataShareHelper(false);
    MockIsFailedGoToFirstRow(0);
    MockGoToGetNextRow(-1);

    AdvancedDatashareHelper advancedDatashareHelper;
    std::string uri = "datashare:///com.ohos.contactsdataability/contacts/contact_data?Proxy=true";
    Uri contactUri(uri);
    std::string phoneNumber = "1111";

    bool ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "4", "1", "true");
    EXPECT_EQ(ret, 1);
}

HWTEST_F(AdvancedDatashareHelperTest, QueryContact_0005, Function | SmallTest | Level1)
{
    MockGetSystemAbilityManager(false);
    MockSetRowCount(0);
    MockIsFailedToCreateDataShareHelper(true);
    MockIsFailedGoToFirstRow(0);

    AdvancedDatashareHelper advancedDatashareHelper;
    std::string uri = "datashare:///com.ohos.contactsdataability/contacts/contact_data?Proxy=true";
    Uri contactUri(uri);
    std::string phoneNumber = "11111111111";
    int32_t userId = 100;

    bool ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "6", "1", "true", userId);
    EXPECT_EQ(ret, 1);

    MockIsFailedToCreateDataShareHelper(false);
    AdvancedDatashareHelper::SetIsDataShareReady(true);
    ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "6", "1", "true", userId);
    EXPECT_EQ(ret, 1);
}

HWTEST_F(AdvancedDatashareHelperTest, QueryContact_0006, Function | SmallTest | Level1)
{
    std::string str = "0";
    MockGetStringValue(str);
    MockGetSystemAbilityManager(false);
    MockIsFailedToQueryDataShareResultSet(false);
    MockIsFailedToCreateDataShareHelper(false);
    MockSetRowCount(1);
    MockGoToGetNextRow(-1);
    MockIsFailedGoToFirstRow(0);

    AdvancedDatashareHelper advancedDatashareHelper;
    std::string uri = advancedDatashareHelper.GetFocusModeRepeatCallUri(0);
    Uri contactUri(uri);
    std::string phoneNumber = "1111";
    int32_t userId = 100;
    AdvancedDatashareHelper::SetIsDataShareReady(true);

    bool ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "5", "1", "true", userId);
    EXPECT_EQ(ret, 0);

    str = "1";
    MockGetStringValue(str);
    ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "5", "1", "true", userId);
    EXPECT_EQ(ret, 1);

    str = "2";
    MockGetStringValue(str);
    ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "5", "1", "true", userId);
    EXPECT_EQ(ret, 0);

    ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "10", "1", "true", userId);
    EXPECT_EQ(ret, 1);
}

HWTEST_F(AdvancedDatashareHelperTest, QueryContact_0007, Function | SmallTest | Level1)
{
    MockGetSystemAbilityManager(false);
    MockIsFailedToCreateDataShareHelper(true);
    MockIsFailedToQueryDataShareResultSet(true);
    MockIsFailedGoToFirstRow(0);
    AdvancedDatashareHelper advancedDatashareHelper;
    std::string uri = advancedDatashareHelper.GetIntelligentExperienceUri(0);
    Uri contactUri(uri);
    std::string phoneNumber = "11111111111";
    int32_t userId = 100;

    int ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "10", "1", "true", userId);
    EXPECT_EQ(ret, -1);

    MockIsFailedToCreateDataShareHelper(false);
    ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "10", "1", "true", userId);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(AdvancedDatashareHelperTest, QueryContact_0008, Function | SmallTest | Level1)
{
    MockGetSystemAbilityManager(false);
    MockSetRowCount(1);
    MockIsFailedToCreateDataShareHelper(false);
    MockIsFailedGoToFirstRow(0);
    MockGoToGetNextRow(-1);

    AdvancedDatashareHelper advancedDatashareHelper;
    std::string uri = "datashare:///com.ohos.contactsdataability/contacts/contact_data?Proxy=true";
    Uri contactUri(uri);
    std::string phoneNumber = "1111";
    int32_t userId = 100;

    bool ret = advancedDatashareHelper.QueryContact(
        contactUri, phoneNumber, "4", "1", "true", userId);
    EXPECT_EQ(ret, 1);
}

HWTEST_F(AdvancedDatashareHelperTest, isRepeatCall_0001, Function | SmallTest | Level1)
{
    MockGetSystemAbilityManager(false);
    MockIsFailedToCreateDataShareHelper(true);
    MockIsFailedToQueryDataShareResultSet(true);

    AdvancedDatashareHelper advancedDatashareHelper;
    std::string phoneNumber = "11111111111";

    bool ret = advancedDatashareHelper.isRepeatCall(phoneNumber);
    EXPECT_EQ(ret, 0);

    MockIsFailedToCreateDataShareHelper(false);
    ret = advancedDatashareHelper.isRepeatCall(phoneNumber);
    EXPECT_EQ(ret, 0);

    MockIsFailedToQueryDataShareResultSet(false);
    MockSetRowCount(1);
    MockIsFailedGoToFirstRow(0);
    ret = advancedDatashareHelper.isRepeatCall(phoneNumber);
    EXPECT_EQ(ret, 0);
}
}
}